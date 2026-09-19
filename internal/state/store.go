// Package state is hull's crash-safe on-disk store for containers, networks
// and volumes.
//
// The daemon can be SIGKILLed at any instant — WSL tears the engine distro down
// without warning — so every mutation here is either fully applied or not
// applied at all. Single records are written with the write-tmp / fsync /
// rename / fsync-dir dance, name reservations are made with symlink(2) (which
// fails atomically with EEXIST), and cross-process serialisation uses advisory
// file locks so a per-container shim and the daemon can never interleave two
// read-modify-write cycles on the same record.
//
// The layout under the store root mirrors docs/ARCHITECTURE.md:
//
//	<root>/hull.lock                  exclusive daemon lock
//	<root>/run/hull.pid               pid of the daemon holding the lock
//	<root>/containers/<id>/state.json types.Container
//	<root>/containers/<id>/state.lock per-container advisory lock
//	<root>/names/<name>               symlink -> ../containers/<id>
//	<root>/networks/networks.json     network index
//	<root>/volumes/volumes.json       volume index
package state

import (
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// DefaultRoot is the store root hull uses unless the daemon is told otherwise.
const DefaultRoot = "/var/lib/hull"

const (
	dirPerm  fs.FileMode = 0o700
	filePerm fs.FileMode = 0o600
)

// Store is an open, exclusively locked hull state directory.
//
// A Store is safe for concurrent use by many goroutines. Cross-process safety
// comes from the advisory locks it takes; a second Store opened on the same
// root by another process fails with ErrAlreadyLocked.
type Store struct {
	root    string
	lock    *os.File
	pidPath string

	logger *slog.Logger

	closeMu sync.Mutex
	closed  bool

	// cmuMu guards cmus, the table of per-container in-process mutexes. The
	// in-process mutex is the cheap half of UpdateContainer's exclusion; the
	// per-container flock is the half that also excludes other processes.
	cmuMu sync.Mutex
	cmus  map[string]*sync.Mutex

	// netMu and volMu guard the two single-file indexes in this process.
	netMu sync.RWMutex
	volMu sync.RWMutex

	// rndMu guards rnd, which GenerateName draws from. Tests replace it with a
	// seeded generator through SetRand to get a deterministic sequence.
	rndMu sync.Mutex
	rnd   *rand.Rand
}

// subdirs is the directory tree Open materialises. Creating the whole layout up
// front means no other subsystem has to race on MkdirAll later.
var subdirs = []string{
	"containers",
	"names",
	"networks",
	"volumes",
	"images",
	"snapshots",
	"run",
	"l", // short symlinked overlay layer names, see ARCHITECTURE.md
	filepath.Join("content", "blobs", "sha256"),
	filepath.Join("content", "ingest"),
}

// Open creates the hull state tree under root if it does not exist, takes an
// exclusive non-blocking flock on <root>/hull.lock, and records the caller's
// pid in <root>/run/hull.pid.
//
// If another process already holds the lock, Open returns a *LockedError (which
// satisfies errors.Is(err, ErrAlreadyLocked)) naming the pid read from the pid
// file, so the operator is told exactly which daemon to stop.
//
// The returned Store must be closed with Close to release the lock.
func Open(root string) (*Store, error) {
	if root == "" {
		root = DefaultRoot
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve state root %q: %w", root, err)
	}
	root = abs

	if err := mkdirAll(root, dirPerm); err != nil {
		return nil, err
	}
	for _, d := range subdirs {
		if err := mkdirAll(filepath.Join(root, d), dirPerm); err != nil {
			return nil, err
		}
	}

	lockPath := filepath.Join(root, "hull.lock")
	lf, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, filePerm)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", lockPath, err)
	}

	pidPath := filepath.Join(root, "run", "hull.pid")
	if err := tryLockFileExclusive(lf); err != nil {
		lf.Close()
		if err == errWouldBlock {
			return nil, &LockedError{Path: lockPath, Pid: readPidFile(pidPath)}
		}
		return nil, fmt.Errorf("lock %s: %w", lockPath, err)
	}

	s := &Store{
		root:    root,
		lock:    lf,
		pidPath: pidPath,
		logger:  slog.Default(),
		cmus:    make(map[string]*sync.Mutex),
		rnd:     rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
	}

	if err := writeFileAtomic(pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), filePerm); err != nil {
		unlockFile(lf)
		lf.Close()
		return nil, fmt.Errorf("write pid file: %w", err)
	}
	return s, nil
}

// readPidFile returns the pid recorded in path, or 0 when it is missing,
// unreadable or not a number. It is only used to make LockedError actionable,
// so a failure here must never mask the lock error itself.
func readPidFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

// SetLogger replaces the logger the store uses to report entries it had to skip
// (an unreadable state.json, a dangling name link). It must be called before
// the store is shared with other goroutines.
func (s *Store) SetLogger(l *slog.Logger) {
	if l != nil {
		s.logger = l
	}
}

// SetRand replaces the random source GenerateName draws from. It exists so
// tests can seed a deterministic generator; production code should leave the
// default in place. It must be called before the store is shared with other
// goroutines.
func (s *Store) SetRand(r *rand.Rand) {
	if r == nil {
		return
	}
	s.rndMu.Lock()
	defer s.rndMu.Unlock()
	s.rnd = r
}

// Close releases the exclusive lock, removes the pid file and makes further use
// of the store an error. Close is idempotent.
func (s *Store) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	// Remove the pid file first: while the lock is still held nobody else can
	// misread a stale pid, and after the unlock the file would be a lie.
	if err := os.Remove(s.pidPath); err != nil && !os.IsNotExist(err) {
		s.logger.Warn("hull: could not remove pid file", "path", s.pidPath, "err", err)
	}
	var firstErr error
	if err := unlockFile(s.lock); err != nil {
		firstErr = fmt.Errorf("unlock %s: %w", s.lock.Name(), err)
	}
	if err := s.lock.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("close %s: %w", s.lock.Name(), err)
	}
	return firstErr
}

// Root returns the absolute path of the state directory.
func (s *Store) Root() string { return s.root }

// ContainerDir returns the directory that holds one container's bundle, rootfs
// overlay dirs, logs and state.json. It does not create the directory and does
// not check that id exists.
func (s *Store) ContainerDir(id string) string {
	return filepath.Join(s.root, "containers", id)
}

// containersDir returns <root>/containers.
func (s *Store) containersDir() string { return filepath.Join(s.root, "containers") }

// namesDir returns <root>/names.
func (s *Store) namesDir() string { return filepath.Join(s.root, "names") }

// checkOpen returns ErrClosed once Close has run.
func (s *Store) checkOpen() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return nil
}

// containerMutex returns the process-local mutex for one container id,
// creating it on first use.
func (s *Store) containerMutex(id string) *sync.Mutex {
	s.cmuMu.Lock()
	defer s.cmuMu.Unlock()
	mu, ok := s.cmus[id]
	if !ok {
		mu = new(sync.Mutex)
		s.cmus[id] = mu
	}
	return mu
}

// forgetContainerMutex drops the process-local mutex for a deleted container so
// the table does not grow without bound over a long daemon lifetime.
func (s *Store) forgetContainerMutex(id string) {
	s.cmuMu.Lock()
	defer s.cmuMu.Unlock()
	delete(s.cmus, id)
}

// fileLock is an acquired advisory lock on a lock file.
type fileLock struct{ f *os.File }

// release unlocks and closes the lock file.
func (l *fileLock) release() {
	if l == nil || l.f == nil {
		return
	}
	unlockFile(l.f)
	l.f.Close()
	l.f = nil
}

// acquireFileLock opens (creating if needed) path and takes a blocking
// exclusive advisory lock on it.
func acquireFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, filePerm)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	if err := lockFileExclusive(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &fileLock{f: f}, nil
}
