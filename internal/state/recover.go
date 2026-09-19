package state

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

// DisappearedProcessError is the Container.Error text hull records for a
// container whose process vanished while the daemon was not running.
const DisappearedProcessError = "container process disappeared while the daemon was not running"

// DisappearedExitCode is the exit code hull records for such a container. 255
// is what Docker uses when it never saw a real wait status.
const DisappearedExitCode = 255

// RecoveryAction is one state transition Recover performed, so the daemon can
// log it and publish the matching "die" event on the event bus.
type RecoveryAction struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	From   types.State `json:"from"`
	To     types.State `json:"to"`
	Reason string      `json:"reason"`
}

// String renders an action as one log-friendly line.
func (a RecoveryAction) String() string {
	name := a.Name
	if name == "" {
		name = a.ID
	}
	return fmt.Sprintf("%s (%s): %s -> %s: %s", name, shortID(a.ID), a.From, a.To, a.Reason)
}

// shortID trims an ID to the 12 characters the CLI displays.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Recover reconciles the on-disk store with reality after a daemon start.
//
// For every container recorded as running or restarting it asks alive whether
// the recorded pid is still that container's process. alive is given both the
// pid and Container.StartedAt so it can reject a recycled pid; pass nil to use
// ProcessAlive, which compares /proc/<pid>/stat field 22 against StartedAt.
// Containers whose process is gone are flipped to exited with exit code 255 and
// an explanatory Error, and each transition is returned as a RecoveryAction.
//
// Recover also sweeps the debris a SIGKILLed daemon leaves behind: staging
// files from an interrupted atomic write (*.tmp), in-progress content-store
// ingests (content/ingest/*), and name reservations that point at container
// directories which no longer exist.
//
// A container directory whose record cannot be read is logged and skipped;
// Recover only returns an error for a failure that makes the whole store
// unusable, or when ctx is cancelled.
func (s *Store) Recover(ctx context.Context, alive func(pid int, startedAt time.Time) bool) ([]RecoveryAction, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if alive == nil {
		alive = ProcessAlive
	}

	// Index staging files first: an interrupted index write must not be left
	// where a later Recover could mistake it for something meaningful.
	s.sweepTmpFiles(filepath.Join(s.root, "networks"))
	s.sweepTmpFiles(filepath.Join(s.root, "volumes"))
	s.sweepIngest()

	entries, err := os.ReadDir(s.containersDir())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan containers for recovery: %w", err)
	}

	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() && validateFullID(e.Name()) == nil {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)

	var actions []RecoveryAction
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return actions, err
		}
		dir := s.ContainerDir(id)
		s.sweepTmpFiles(dir)

		c, err := readContainerAt(dir)
		if err != nil {
			s.logger.Warn("hull: recovery skipping unreadable container record", "id", id, "err", err)
			continue
		}
		if c.State != types.StateRunning && c.State != types.StateRestarting {
			continue
		}
		if alive(c.Pid, c.StartedAt) {
			continue
		}

		from := c.State
		now := time.Now().UTC()
		if err := s.UpdateContainer(id, func(cur *types.Container) error {
			if cur.State != types.StateRunning && cur.State != types.StateRestarting {
				return errSkipRecovery
			}
			cur.State = types.StateExited
			cur.ExitCode = DisappearedExitCode
			cur.Error = DisappearedProcessError
			cur.Pid = 0
			if cur.FinishedAt.IsZero() || cur.FinishedAt.Before(cur.StartedAt) {
				cur.FinishedAt = now
			}
			if cur.Health != nil && cur.Health.Status == "healthy" {
				cur.Health.Status = "unhealthy"
			}
			return nil
		}); err != nil {
			if errors.Is(err, errSkipRecovery) {
				continue
			}
			s.logger.Warn("hull: recovery could not update container", "id", id, "err", err)
			continue
		}

		actions = append(actions, RecoveryAction{
			ID:     id,
			Name:   c.Name,
			From:   from,
			To:     types.StateExited,
			Reason: DisappearedProcessError,
		})
	}

	s.sweepNames()
	return actions, nil
}

// errSkipRecovery aborts an UpdateContainer callback without writing, when the
// record turned out to have already been fixed by someone else.
var errSkipRecovery = errors.New("state: container no longer needs recovery")

// sweepTmpFiles deletes leftover *.tmp staging files in dir. A staging file is
// by definition an incomplete write, so it carries no information worth
// keeping; the record it was going to replace is still intact.
func (s *Store) sweepTmpFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.logger.Warn("hull: recovery could not scan directory", "dir", dir, "err", err)
		}
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), tmpSuffix) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.logger.Warn("hull: recovery could not remove staging file", "path", p, "err", err)
			continue
		}
		s.logger.Info("hull: recovery removed staging file", "path", p)
	}
}

// sweepIngest empties <root>/content/ingest. Every entry there is a blob
// download that a dead daemon never finished verifying, so none of them may be
// promoted into the content store; the next pull re-fetches them.
func (s *Store) sweepIngest() {
	dir := filepath.Join(s.root, "content", "ingest")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.logger.Warn("hull: recovery could not scan the ingest directory", "dir", dir, "err", err)
		}
		return
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if err := os.RemoveAll(p); err != nil {
			s.logger.Warn("hull: recovery could not remove ingest leftover", "path", p, "err", err)
			continue
		}
		s.logger.Info("hull: recovery removed unfinished ingest", "path", p)
	}
}

// sweepNames removes name reservations whose container directory is gone, which
// is what a crash between "remove the container" and "release the name" leaves
// behind. Without this the name would stay reserved forever.
func (s *Store) sweepNames() {
	dir := s.namesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.logger.Warn("hull: recovery could not scan the names directory", "dir", dir, "err", err)
		}
		return
	}
	for _, e := range entries {
		name := e.Name()
		link := filepath.Join(dir, name)
		target, err := os.Readlink(link)
		drop := false
		switch {
		case err != nil:
			s.logger.Warn("hull: recovery found a names entry that is not a symlink", "name", name, "err", err)
			drop = true
		default:
			id := idFromTarget(target)
			if validateFullID(id) != nil {
				drop = true
				break
			}
			if fi, serr := os.Stat(s.ContainerDir(id)); serr != nil || !fi.IsDir() {
				drop = true
			}
		}
		if !drop {
			continue
		}
		if err := os.Remove(link); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.logger.Warn("hull: recovery could not remove dangling name", "name", name, "err", err)
			continue
		}
		s.logger.Info("hull: recovery released a dangling name reservation", "name", name)
	}
}
