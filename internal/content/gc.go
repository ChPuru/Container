package content

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
)

// GCLockName is the file under the store root whose exclusive flock serialises
// garbage collection against pulls and other collectors.
const GCLockName = "gc.lock"

// GCResult summarises one garbage-collection pass.
type GCResult struct {
	// Deleted is how many blobs were removed.
	Deleted int `json:"deleted"`
	// FreedBytes is how many bytes those blobs occupied.
	FreedBytes int64 `json:"freedBytes"`
	// Kept is how many blobs were reachable and survived.
	Kept int `json:"kept"`
}

// LockPath returns the path of the garbage-collection lock file.
func (s *Store) LockPath() string { return filepath.Join(s.root, GCLockName) }

// Lock takes the exclusive store lock and returns a function that releases it.
// A pull should hold it while it commits the blobs of an image so that a
// concurrent GC cannot delete a blob that is written but not yet referenced.
func (s *Store) Lock(ctx context.Context) (func() error, error) {
	l, err := acquireLock(ctx, s.LockPath())
	if err != nil {
		return nil, err
	}
	return l.release, nil
}

// GC deletes every blob that is not reachable from roots.
//
// roots are digests known to be live (image manifests, image configs, anything
// the image index still names). reachable is asked, for each digest visited,
// which further digests that blob refers to — for a manifest, its config and
// layer digests. It may be nil, in which case only the roots survive.
//
// GC holds an exclusive flock on <root>/gc.lock for the whole pass so it can
// never race a pull that is committing blobs. It is fail-closed: if reachable
// returns an error the pass is abandoned and nothing is deleted, because an
// incomplete reachability graph would delete live content.
func (s *Store) GC(ctx context.Context, roots []string, reachable func(string) ([]string, error)) (GCResult, error) {
	if ctx == nil {
		return GCResult{}, errors.New("content: GC requires a non-nil context")
	}
	unlock, err := s.Lock(ctx)
	if err != nil {
		return GCResult{}, err
	}
	defer unlock()

	marked, err := s.mark(ctx, roots, reachable)
	if err != nil {
		return GCResult{}, err
	}
	return s.sweep(ctx, marked)
}

// mark walks the reachability graph breadth-first from roots.
func (s *Store) mark(ctx context.Context, roots []string, reachable func(string) ([]string, error)) (map[string]struct{}, error) {
	marked := make(map[string]struct{}, len(roots))
	queue := make([]string, 0, len(roots))

	push := func(dgst string) error {
		if err := ValidateDigest(dgst); err != nil {
			return err
		}
		if _, seen := marked[dgst]; seen {
			return nil
		}
		marked[dgst] = struct{}{}
		queue = append(queue, dgst)
		return nil
	}

	for _, r := range roots {
		if err := push(r); err != nil {
			return nil, fmt.Errorf("content: GC root: %w", err)
		}
	}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("content: GC mark phase: %w", err)
		}
		dgst := queue[0]
		queue = queue[1:]
		if reachable == nil {
			continue
		}
		children, err := reachable(dgst)
		if err != nil {
			return nil, fmt.Errorf("content: GC resolving references of %s: %w", dgst, err)
		}
		for _, c := range children {
			if err := push(c); err != nil {
				return nil, fmt.Errorf("content: GC reference from %s: %w", dgst, err)
			}
		}
	}
	return marked, nil
}

// sweep deletes every committed blob that is not in marked.
func (s *Store) sweep(ctx context.Context, marked map[string]struct{}) (GCResult, error) {
	var (
		res  GCResult
		errs []error
	)
	walkErr := s.Walk(func(i Info) error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("content: GC sweep phase: %w", err)
		}
		if _, live := marked[i.Digest]; live {
			res.Kept++
			return nil
		}
		if err := s.Delete(i.Digest); err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil // raced with another deleter
			}
			errs = append(errs, err)
			return nil
		}
		res.Deleted++
		res.FreedBytes += i.Size
		return nil
	})
	if walkErr != nil {
		return res, walkErr
	}
	if err := errors.Join(errs...); err != nil {
		return res, err
	}
	return res, nil
}
