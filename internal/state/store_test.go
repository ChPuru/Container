package state

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

// quietLogger discards store warnings so a test that deliberately corrupts a
// record does not spam the test output.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestStore opens a store on a fresh temporary root and closes it when the
// test ends.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.SetLogger(quietLogger())
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

// sampleContainer builds a fully populated container record.
func sampleContainer(id, name string) *types.Container {
	return &types.Container{
		ID:       id,
		Name:     name,
		Created:  time.Unix(1700000000, 0).UTC(),
		Image:    "sha256:" + strings.Repeat("a", 64),
		ImageRef: "alpine:3.20",
		Config: types.ContainerConfig{
			Hostname: name,
			Env:      []string{"PATH=/usr/bin", "TERM=xterm"},
			Cmd:      []string{"/bin/sh", "-c", "sleep 1"},
			Labels:   map[string]string{"app": "demo"},
		},
		HostConfig: types.HostConfig{
			NetworkMode: "bridge",
			Resources:   types.Resources{Memory: 256 << 20, CPUShares: 512},
			LogConfig:   types.LogConfig{Type: "json-file"},
		},
		State:      types.StateCreated,
		SnapshotID: "chain-1",
		NetworkSettings: types.NetworkSettings{
			Networks: map[string]types.EndpointSettings{
				"hull0": {IPAddress: "10.66.0.2", IPPrefixLen: 24},
			},
		},
	}
}

func TestOpenCreatesTreeAndTakesExclusiveLock(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	for _, d := range subdirs {
		if fi, err := os.Stat(filepath.Join(root, d)); err != nil || !fi.IsDir() {
			t.Errorf("subdir %q missing: %v", d, err)
		}
	}
	if s.Root() != root {
		t.Errorf("Root() = %q, want %q", s.Root(), root)
	}
	want := filepath.Join(root, "containers", "abc")
	if got := s.ContainerDir("abc"); got != want {
		t.Errorf("ContainerDir = %q, want %q", got, want)
	}
	if got := readPidFile(filepath.Join(root, "run", "hull.pid")); got != os.Getpid() {
		t.Errorf("pid file = %d, want %d", got, os.Getpid())
	}

	// A second daemon must be refused, and told which pid holds the lock.
	second, err := Open(root)
	if err == nil {
		second.Close()
		t.Fatal("second Open succeeded, want ErrAlreadyLocked")
	}
	if !errors.Is(err, ErrAlreadyLocked) {
		t.Fatalf("second Open error = %v, want ErrAlreadyLocked", err)
	}
	var le *LockedError
	if !errors.As(err, &le) {
		t.Fatalf("second Open error is not *LockedError: %v", err)
	}
	if le.Pid != os.Getpid() {
		t.Errorf("LockedError.Pid = %d, want %d", le.Pid, os.Getpid())
	}
	if !strings.Contains(le.Error(), "hull.lock") {
		t.Errorf("LockedError message %q does not name the lock file", le.Error())
	}

	// After Close the lock and the pid file are gone.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "run", "hull.pid")); !os.IsNotExist(err) {
		t.Errorf("pid file still present after Close: %v", err)
	}
	third, err := Open(root)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	third.Close()
}

func TestClosedStoreRejectsOperations(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := s.ListContainers(); !errors.Is(err, ErrClosed) {
		t.Errorf("ListContainers after Close = %v, want ErrClosed", err)
	}
	if err := s.PutContainer(sampleContainer(NewID(), "x")); !errors.Is(err, ErrClosed) {
		t.Errorf("PutContainer after Close = %v, want ErrClosed", err)
	}
}

func TestContainerRoundTrip(t *testing.T) {
	s := newTestStore(t)
	id := NewID()
	want := sampleContainer(id, "round_trip")

	if err := s.PutContainer(want); err != nil {
		t.Fatalf("PutContainer: %v", err)
	}
	if err := s.ReserveName(want.Name, id); err != nil {
		t.Fatalf("ReserveName: %v", err)
	}

	for _, ref := range []string{id, id[:12], want.Name, "/" + want.Name} {
		got, err := s.GetContainer(ref)
		if err != nil {
			t.Fatalf("GetContainer(%q): %v", ref, err)
		}
		if got.ID != want.ID || got.Name != want.Name || got.ImageRef != want.ImageRef {
			t.Errorf("GetContainer(%q) = %+v, want id/name/imageRef of %+v", ref, got, want)
		}
		if !got.Created.Equal(want.Created) {
			t.Errorf("Created = %v, want %v", got.Created, want.Created)
		}
		if got.HostConfig.Resources.Memory != want.HostConfig.Resources.Memory {
			t.Errorf("Memory = %d, want %d", got.HostConfig.Resources.Memory, want.HostConfig.Resources.Memory)
		}
		if got.NetworkSettings.Networks["hull0"].IPAddress != "10.66.0.2" {
			t.Errorf("network settings lost: %+v", got.NetworkSettings)
		}
		if len(got.Config.Cmd) != 3 {
			t.Errorf("Cmd = %v, want 3 elements", got.Config.Cmd)
		}
	}

	list, err := s.ListContainers()
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("ListContainers = %v, want one entry %s", list, id)
	}

	if err := s.DeleteContainer(id); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	if _, err := s.GetContainer(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetContainer after delete = %v, want ErrNotFound", err)
	}
	if _, err := s.lookupName(want.Name); !errors.Is(err, ErrNotFound) {
		t.Errorf("name survived DeleteContainer: %v", err)
	}
	if err := s.DeleteContainer(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteContainer = %v, want ErrNotFound", err)
	}
}

func TestPutContainerRejectsBadID(t *testing.T) {
	s := newTestStore(t)
	tests := []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"too short", "abcd"},
		{"uppercase", strings.Repeat("A", 64)},
		{"traversal", "../../etc/passwd"},
		{"slash", strings.Repeat("a", 63) + "/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := s.PutContainer(sampleContainer(tc.id, "bad_id"))
			if !errors.Is(err, ErrInvalidID) {
				t.Fatalf("PutContainer(%q) = %v, want ErrInvalidID", tc.id, err)
			}
		})
	}
}

// TestAtomicWriteSurvivesSimulatedCrash writes a record, then simulates a
// daemon killed mid-write by leaving a truncated state.json.tmp behind, and
// checks that a freshly opened store still reads the previous complete record
// and that Recover sweeps the staging file away.
func TestAtomicWriteSurvivesSimulatedCrash(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.SetLogger(quietLogger())

	id := NewID()
	good := sampleContainer(id, "durable_one")
	if err := s.PutContainer(good); err != nil {
		t.Fatalf("PutContainer: %v", err)
	}

	// Crash in the middle of the next write: the staging file exists and is
	// half a JSON document, and the rename never happened.
	tmpPath := filepath.Join(s.ContainerDir(id), stateFile+tmpSuffix)
	if err := os.WriteFile(tmpPath, []byte(`{"id":"`+id+`","state":"run`), 0o600); err != nil {
		t.Fatalf("write staging file: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s2.SetLogger(quietLogger())
	defer s2.Close()

	got, err := s2.GetContainer(id)
	if err != nil {
		t.Fatalf("GetContainer after crash: %v", err)
	}
	if got.State != types.StateCreated || got.Name != "durable_one" {
		t.Fatalf("record was corrupted by the interrupted write: %+v", got)
	}

	if _, err := s2.Recover(t.Context(), func(int, time.Time) bool { return true }); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("staging file survived Recover: %v", err)
	}
	if list, err := s2.ListContainers(); err != nil || len(list) != 1 {
		t.Errorf("ListContainers = %v (%v), want 1 entry", list, err)
	}
}

func TestResolve(t *testing.T) {
	s := newTestStore(t)

	// Two IDs sharing a long prefix, plus one that does not.
	idA := "aaa1" + strings.Repeat("0", 60)
	idB := "aaa2" + strings.Repeat("0", 60)
	idC := "bbbb" + strings.Repeat("f", 60)
	for _, id := range []string{idA, idB, idC} {
		if err := s.PutContainer(sampleContainer(id, "")); err != nil {
			t.Fatalf("PutContainer(%s): %v", id, err)
		}
	}
	if err := s.ReserveName("web", idC); err != nil {
		t.Fatalf("ReserveName: %v", err)
	}

	tests := []struct {
		name    string
		ref     string
		want    string
		wantErr error
	}{
		{"exact id", idA, idA, nil},
		{"exact name", "web", idC, nil},
		{"slashed name", "/web", idC, nil},
		{"unique prefix", "aaa1", idA, nil},
		{"unique prefix long", idB[:20], idB, nil},
		{"unique prefix other", "bbb", idC, nil},
		{"ambiguous prefix", "aaa", "", ErrAmbiguous},
		{"too short prefix", "aa", "", ErrNotFound},
		{"unknown id", strings.Repeat("c", 64), "", ErrNotFound},
		{"unknown name", "nosuchname", "", ErrNotFound},
		{"empty", "", "", ErrNotFound},
		{"traversal", "../../etc", "", ErrNotFound},
		{"absolute", "/etc/passwd", "", ErrNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.Resolve(tc.ref)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Resolve(%q) error = %v, want %v", tc.ref, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.ref, err)
			}
			if got != tc.want {
				t.Fatalf("Resolve(%q) = %s, want %s", tc.ref, got, tc.want)
			}
		})
	}

	// The ambiguity error must list every candidate so the CLI can print them.
	_, err := s.Resolve("aaa")
	var amb *AmbiguousError
	if !errors.As(err, &amb) {
		t.Fatalf("Resolve(\"aaa\") error is not *AmbiguousError: %v", err)
	}
	if len(amb.Matches) != 2 {
		t.Fatalf("AmbiguousError.Matches = %v, want 2 entries", amb.Matches)
	}
	if !strings.Contains(amb.Error(), idA) || !strings.Contains(amb.Error(), idB) {
		t.Errorf("AmbiguousError message does not list both matches: %s", amb.Error())
	}
}

func TestListContainersSkipsUnreadableEntries(t *testing.T) {
	s := newTestStore(t)
	good := NewID()
	if err := s.PutContainer(sampleContainer(good, "good_one")); err != nil {
		t.Fatalf("PutContainer: %v", err)
	}

	// A container directory whose record is corrupt.
	broken := NewID()
	bdir := s.ContainerDir(broken)
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bdir, stateFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A container directory with no record at all.
	if err := os.MkdirAll(s.ContainerDir(NewID()), 0o700); err != nil {
		t.Fatal(err)
	}
	// A stray file that is not a container directory.
	if err := os.WriteFile(filepath.Join(s.containersDir(), "README"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListContainers()
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(list) != 1 || list[0].ID != good {
		t.Fatalf("ListContainers = %v, want only %s", list, good)
	}
}

func TestListContainersSortsNewestFirst(t *testing.T) {
	s := newTestStore(t)
	base := time.Unix(1700000000, 0).UTC()
	var ids []string
	for i := range 3 {
		id := NewID()
		ids = append(ids, id)
		c := sampleContainer(id, "")
		c.Created = base.Add(time.Duration(i) * time.Minute)
		if err := s.PutContainer(c); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListContainers()
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d containers, want 3", len(list))
	}
	if list[0].ID != ids[2] || list[2].ID != ids[0] {
		t.Errorf("not sorted newest first: %s ... %s", list[0].ID, list[2].ID)
	}
}

func TestUpdateContainer(t *testing.T) {
	s := newTestStore(t)
	id := NewID()
	if err := s.PutContainer(sampleContainer(id, "updater")); err != nil {
		t.Fatalf("PutContainer: %v", err)
	}

	if err := s.UpdateContainer(id[:12], func(c *types.Container) error {
		c.State = types.StateRunning
		c.Pid = 4242
		return nil
	}); err != nil {
		t.Fatalf("UpdateContainer: %v", err)
	}
	got, err := s.GetContainer(id)
	if err != nil {
		t.Fatalf("GetContainer: %v", err)
	}
	if got.State != types.StateRunning || got.Pid != 4242 {
		t.Fatalf("update not persisted: %+v", got)
	}

	// A callback error must abort the write.
	boom := errors.New("boom")
	if err := s.UpdateContainer(id, func(c *types.Container) error {
		c.Pid = 1
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("UpdateContainer error = %v, want boom", err)
	}
	got, err = s.GetContainer(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pid != 4242 {
		t.Fatalf("aborted update was written anyway: pid=%d", got.Pid)
	}

	if err := s.UpdateContainer(strings.Repeat("d", 64), func(*types.Container) error {
		return nil
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateContainer on missing container = %v, want ErrNotFound", err)
	}
}

// TestConcurrentUpdateContainer runs 50 goroutines through UpdateContainer and
// checks that every increment landed: no lost update, and the record on disk is
// still valid JSON.
func TestConcurrentUpdateContainer(t *testing.T) {
	s := newTestStore(t)
	id := NewID()
	if err := s.PutContainer(sampleContainer(id, "hammer")); err != nil {
		t.Fatalf("PutContainer: %v", err)
	}

	const workers = 50
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	start := make(chan struct{})
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			err := s.UpdateContainer(id, func(c *types.Container) error {
				c.RestartCount++
				c.Config.Env = append(c.Config.Env, "N="+strings.Repeat("x", i))
				return nil
			})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent UpdateContainer: %v", err)
	}

	got, err := s.GetContainer(id)
	if err != nil {
		t.Fatalf("GetContainer: %v", err)
	}
	if got.RestartCount != workers {
		t.Fatalf("RestartCount = %d, want %d (an update was lost)", got.RestartCount, workers)
	}
	if len(got.Config.Env) != 2+workers {
		t.Fatalf("Env has %d entries, want %d", len(got.Config.Env), 2+workers)
	}
	if got.ID != id || got.Name != "hammer" {
		t.Fatalf("record was mangled: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(s.ContainerDir(id), stateFile+tmpSuffix)); !os.IsNotExist(err) {
		t.Errorf("staging file left behind: %v", err)
	}
}
