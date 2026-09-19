// Package snapshot implements hull's overlayfs snapshotter.
//
// A snapshotter turns a stack of immutable image layers into a writable
// container rootfs, and is the foundation of hull's snapshot / time-travel
// differentiator.
//
// # On-disk layout
//
// Everything lives under one root, normally /var/lib/hull:
//
//	snapshots/<chainID-hex>/fs        the extracted, read-only layer
//	snapshots/<chainID-hex>/.complete written last; absence means "re-extract"
//	snapshots/<chainID-hex>/meta.json the Info record for the snapshot
//	snapshots/<chainID-hex>/link      the short link name allocated for it
//	containers/<id>/{upper,work,merged}
//	checkpoints/<id>/<name>/upper     a frozen copy of a container's upperdir
//	l/<n>                             short symlinks to snapshots/<chainID>/fs
//	mounts.json                       the mounts this root believes are live
//
// # Why l/
//
// The legacy mount(2) option string is copied with copy_mount_options, which
// reads at most one page: 4095 usable bytes. A 40-layer image whose lowerdir
// list is written out as full chain-ID paths needs roughly 3 KB on its own, and
// 60 layers do not fit at all. Every layer therefore gets a two- or
// three-character name under l/ pointing at its fs directory, exactly as
// Docker's overlay2 driver and containerd do, and the lowerdir list is built
// from those.
//
// # Layer extraction
//
// Each layer is extracted into its own directory holding only that layer's own
// files, the way containerd stores them, so that Mount can stack them. A layer
// tar expresses a deletion with the AUFS marker ".wh.<name>"; on disk overlayfs
// wants a character device with device number 0:0, and an opaque directory
// wants the trusted.overlay.opaque xattr (user.overlay.opaque when the overlay
// is rootless). Unpack performs that translation itself rather than deleting
// anything, because there is nothing to delete in a per-layer directory: the
// parent's files live in the parent's directory.
//
// # Security
//
// Layer contents and container upperdirs are attacker-controlled. Every path
// inside one is resolved fd-relative with openat2(RESOLVE_IN_ROOT) through
// internal/fsutil, or walked with O_NOFOLLOW one component at a time. No
// container-controlled path is ever handed to filepath.Join plus os.Open.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Directory and file names under the snapshotter root.
const (
	// DirSnapshots holds one directory per committed layer, named by chain ID.
	DirSnapshots = "snapshots"
	// DirContainers holds the per-container upper, work and merged directories.
	DirContainers = "containers"
	// DirCheckpoints holds per-container named checkpoints of an upperdir.
	DirCheckpoints = "checkpoints"
	// DirLinks is the short-symlink directory that keeps mount option strings
	// inside one page.
	DirLinks = "l"
	// DirFS is the name of the extracted layer directory inside a snapshot.
	DirFS = "fs"
	// DirUpper is the overlay upperdir inside a container directory.
	DirUpper = "upper"
	// DirWork is the overlay workdir inside a container directory.
	DirWork = "work"
	// DirMerged is the overlay mountpoint inside a container directory.
	DirMerged = "merged"
	// DirStack holds the intermediate mountpoints of a nested lower stack.
	DirStack = "stack"

	// FileComplete is the commit marker. Its absence means the snapshot is
	// partial and must be extracted again.
	FileComplete = ".complete"
	// FileMeta is the per-snapshot Info record.
	FileMeta = "meta.json"
	// FileParent records the parent chain ID between Prepare and Commit, so a
	// Commit that follows a daemon restart still knows the parent.
	FileParent = ".parent"
	// FileLock is the per-chain-ID lock that serialises concurrent extraction.
	FileLock = ".lock"
	// FileLink holds the short link name allocated to a snapshot.
	FileLink = "link"
	// FileMounts is the root-level record of live mounts, so a daemon restart
	// can unmount what the previous process left behind.
	FileMounts = "mounts.json"
	// FileMountsLock guards FileMounts across processes.
	FileMountsLock = ".mounts.lock"
	// FileLinksLock guards short-link allocation across processes.
	FileLinksLock = ".links.lock"
)

// MaxMountOptions is the usable length of a mount(2) option string. The kernel
// copies the data argument with copy_mount_options, which reads one page and
// requires a terminating NUL, so 4095 bytes is the real ceiling.
const MaxMountOptions = 4095

// Snapshot kinds recorded in meta.json.
const (
	// SnapshotKindLayer is a committed, immutable image layer.
	SnapshotKindLayer = "layer"
	// SnapshotKindActive is a writable snapshot being extracted into.
	SnapshotKindActive = "active"
	// SnapshotKindView is a read-only view of an existing chain.
	SnapshotKindView = "view"
)

// dirPerm is the mode of every directory the snapshotter creates at the top
// level. A container's upperdir may hold secrets the container wrote, so the
// bookkeeping directories are owner-only.
const dirPerm os.FileMode = 0o700

// layerDirPerm is the mode of an extracted layer's fs directory and of the
// short-link directory. Both have to be traversable by whatever uid the
// container runs as once the overlay is mounted.
const layerDirPerm os.FileMode = 0o755

// filePerm is the mode of the small bookkeeping files.
const filePerm os.FileMode = 0o644

// Errors returned by this package. All are wrapped with %w.
var (
	// ErrNotFound means the snapshot, container mount or checkpoint does not exist.
	ErrNotFound = errors.New("snapshot: not found")
	// ErrExists means a committed snapshot or checkpoint with that name already exists.
	ErrExists = errors.New("snapshot: already exists")
	// ErrInUse means something still references the object: a live mount, or a
	// child snapshot that stacks on top of it.
	ErrInUse = errors.New("snapshot: still in use")
	// ErrMounted means the operation needs the container's merged directory to
	// be unmounted first.
	ErrMounted = errors.New("snapshot: container rootfs is still mounted")
	// ErrNotPrepared means Commit or Abort was called for a chain ID that this
	// process never prepared.
	ErrNotPrepared = errors.New("snapshot: chain ID was not prepared by this process")
	// ErrOverlayUnsupported means overlayfs cannot be used on this host, with
	// the probe's diagnosis wrapped around it.
	ErrOverlayUnsupported = errors.New("snapshot: overlayfs is not usable here")
	// ErrInvalidChainID means a chain or diff ID is not "sha256:<64 hex>".
	ErrInvalidChainID = errors.New("snapshot: invalid chain ID")
	// ErrOptionsTooLong means the overlay option string exceeds one page even
	// after short links and a nested lower stack.
	ErrOptionsTooLong = errors.New("snapshot: overlay mount options exceed one page")
	// ErrDiffIDMismatch means an extracted layer did not hash to the DiffID the
	// image config promised.
	ErrDiffIDMismatch = errors.New("snapshot: extracted layer does not match its DiffID")
	// ErrWhiteoutUnsupported means an overlay whiteout could not be created,
	// which makes it impossible to record a layer's deletions faithfully.
	ErrWhiteoutUnsupported = errors.New("snapshot: cannot create overlay whiteouts")
	// ErrUnsupportedPlatform means this build of hull is not Linux, so there is
	// no overlayfs to drive.
	ErrUnsupportedPlatform = errors.New("snapshot: the snapshotter requires Linux")
)

// Info describes one snapshot. It is exactly what meta.json holds, plus Refs,
// which is computed from the live mount records rather than stored.
type Info struct {
	// ChainID is the canonical "sha256:<hex>" chain ID naming the snapshot.
	ChainID string `json:"chainID"`
	// DiffID is the digest of the uncompressed layer tar this snapshot holds.
	DiffID string `json:"diffID"`
	// Parent is the chain ID of the snapshot below this one, empty for a base layer.
	Parent string `json:"parent,omitempty"`
	// Size is the uncompressed size of the layer tar in bytes.
	Size int64 `json:"size"`
	// Created is when the snapshot was committed.
	Created time.Time `json:"created"`
	// Kind is one of SnapshotKindLayer, SnapshotKindActive or SnapshotKindView.
	Kind string `json:"kind"`
	// Refs counts the live container mounts whose lower chain contains this
	// snapshot. It is computed by List and never persisted.
	Refs int `json:"refs,omitempty"`
}

// Checkpoint is a named, frozen copy of a container's overlay upperdir: the
// unit hull's time travel operates on.
type Checkpoint struct {
	// Name is the checkpoint's name within its container.
	Name string `json:"name"`
	// ContainerID is the container the checkpoint was taken from.
	ContainerID string `json:"containerID"`
	// Created is when the checkpoint was taken.
	Created time.Time `json:"created"`
	// Size is the apparent size in bytes of the captured upperdir.
	Size int64 `json:"size"`
	// Parent is the chain ID of the image the container was created from, so a
	// Restore can tell that a checkpoint belongs to a different image.
	Parent string `json:"parent,omitempty"`
}

// ChangeKind classifies one entry in a filesystem diff.
type ChangeKind string

// The three kinds of change an overlay upperdir can express.
const (
	// KindAdded means the path exists above and not below.
	KindAdded ChangeKind = "added"
	// KindModified means the path exists in both and differs.
	KindModified ChangeKind = "modified"
	// KindDeleted means the path was removed: on disk, an overlay whiteout,
	// which is a character device with device number 0:0.
	KindDeleted ChangeKind = "deleted"
)

// String returns the change kind as text.
func (k ChangeKind) String() string { return string(k) }

// Letter returns the single-character form Docker's API uses: "A", "C" or "D".
func (k ChangeKind) Letter() string {
	switch k {
	case KindAdded:
		return "A"
	case KindDeleted:
		return "D"
	default:
		return "C"
	}
}

// Change is one path that differs between two filesystem states. Paths are
// absolute inside the container, so they start with "/".
type Change struct {
	// Path is the container-absolute path that changed.
	Path string `json:"path"`
	// Kind says how it changed.
	Kind ChangeKind `json:"kind"`
}

// Features is what the snapshotter needs to know about overlayfs on this host.
// It deliberately mirrors the shape of hostinfo.OverlayInfo so a caller that
// already ran `hull doctor` can copy the fields across one by one, without this
// package having to import the probe.
type Features struct {
	// Supported is true when "overlay" appears in /proc/filesystems.
	Supported bool `json:"supported"`
	// UserXattr reports that hull must pass the userxattr mount option here,
	// which is the case inside a user namespace on 5.11 and later.
	UserXattr bool `json:"userxattr"`
	// UserNS is true when the process runs in a non-identity user namespace.
	UserNS bool `json:"userns"`
	// Redirect is the redirect_dir module parameter; empty when absent.
	Redirect string `json:"redirectDir,omitempty"`
	// Metacopy is the metacopy module parameter.
	Metacopy string `json:"metacopy,omitempty"`
	// Index is the index module parameter.
	Index string `json:"index,omitempty"`
	// Xino is the xino_auto module parameter.
	Xino string `json:"xino,omitempty"`
	// RedirectAlwaysFollow is the redirect_always_follow module parameter. When
	// it is Y the kernel follows redirects even with redirect_dir=off, which is
	// why hull always spells the three semantics-changing options out.
	RedirectAlwaysFollow string `json:"redirectAlwaysFollow,omitempty"`
	// LowerdirPlus reports support for the lowerdir+= syntax (6.7+).
	LowerdirPlus bool `json:"lowerdirPlus"`
	// IdmappedLayers reports support for idmapped overlay lower layers (5.19+).
	IdmappedLayers bool `json:"idmappedLayers"`
	// KernelRelease is the uname release string the version flags came from.
	KernelRelease string `json:"kernelRelease,omitempty"`
	// MountTested is true when a throwaway overlay mount was actually attempted.
	MountTested bool `json:"mountTested"`
	// MountOK is the result of that mount.
	MountOK bool `json:"mountOK"`
	// MountError carries the failure when MountTested is true and MountOK false.
	MountError string `json:"mountError,omitempty"`
}

// Err returns an actionable error when overlayfs cannot be used, and nil when
// it can. It never degrades silently: a caller that gets nil may mount.
func (f Features) Err() error {
	switch {
	case !f.Supported:
		return fmt.Errorf("%w: the kernel does not list \"overlay\" in /proc/filesystems; "+
			"run `wsl --update` for a kernel built with CONFIG_OVERLAY_FS=y", ErrOverlayUnsupported)
	case !f.MountTested:
		return fmt.Errorf("%w: overlayfs was never probed; call Detect, or pass a probed Features to New",
			ErrOverlayUnsupported)
	case !f.MountOK:
		return fmt.Errorf("%w: a throwaway overlay mount under hull's root failed: %s; "+
			"hull's root must be on a filesystem that can host an overlay upperdir (ext4 or btrfs), "+
			"not on a 9p/drvfs Windows drive such as /mnt/c or /mnt/d, and mounting needs CAP_SYS_ADMIN "+
			"(run hulld as root, or inside a user namespace that has it)", ErrOverlayUnsupported, f.MountError)
	}
	return nil
}

// prep is one in-flight Prepare, held until Commit or Abort. done is closed
// when the slot is released, which is how a second goroutine asking for the
// same chain ID learns it may try again.
type prep struct {
	parent string
	unlock func() error
	done   chan struct{}
}

// Snapshotter manages layer snapshots and container rootfs mounts under one
// root directory. It is safe for concurrent use by multiple goroutines, and
// safe for concurrent use by multiple processes: extraction is serialised with
// a per-chain-ID flock and the mount record with a root-level flock.
type Snapshotter struct {
	root string
	feat Features

	mu    sync.Mutex
	preps map[string]*prep
}

// Root returns the directory the snapshotter manages.
func (s *Snapshotter) Root() string { return s.root }

// Features returns the overlay facts the snapshotter was built with.
func (s *Snapshotter) Features() Features { return s.feat }

// SnapshotDir returns the directory holding one snapshot's fs, meta.json and
// commit marker. The chain ID may be given with or without the "sha256:" prefix.
func (s *Snapshotter) SnapshotDir(chainID string) (string, error) {
	h, err := chainHex(chainID)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.root, DirSnapshots, h), nil
}

// FSDir returns the extracted-layer directory of one snapshot.
func (s *Snapshotter) FSDir(chainID string) (string, error) {
	d, err := s.SnapshotDir(chainID)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, DirFS), nil
}

// ContainerDir returns the directory holding one container's upper, work and
// merged directories.
func (s *Snapshotter) ContainerDir(containerID string) (string, error) {
	if err := validateName("container ID", containerID); err != nil {
		return "", err
	}
	return filepath.Join(s.root, DirContainers, containerID), nil
}

// MergedPath returns where a container's rootfs is, or would be, mounted.
func (s *Snapshotter) MergedPath(containerID string) (string, error) {
	d, err := s.ContainerDir(containerID)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, DirMerged), nil
}

// UpperPath returns a container's overlay upperdir.
func (s *Snapshotter) UpperPath(containerID string) (string, error) {
	d, err := s.ContainerDir(containerID)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, DirUpper), nil
}

// Exists reports whether a snapshot is committed and therefore usable as a
// lower layer. A directory without the .complete marker is a partial extraction
// left behind by a crash and is deliberately reported as absent, so that the
// caller extracts it again.
func (s *Snapshotter) Exists(chainID string) bool {
	d, err := s.SnapshotDir(chainID)
	if err != nil {
		return false
	}
	fi, err := os.Stat(filepath.Join(d, FileComplete))
	return err == nil && fi.Mode().IsRegular()
}

// ---------- chain IDs ----------

// ChainID computes the OCI chain ID of a layer from its parent's chain ID and
// its own DiffID, following image-spec v1.1.1:
//
//	ChainID(L0)     = DiffID(L0)
//	ChainID(L0..Ln) = sha256hex(ChainID(L0..Ln-1) + " " + DiffID(Ln))
//
// An empty parent means the layer is the base of the chain, in which case the
// chain ID is the DiffID itself. Both arguments may be given with or without
// the "sha256:" prefix; the result is always canonical.
func ChainID(parent, diffID string) (string, error) {
	d, err := NormalizeDigest(diffID)
	if err != nil {
		return "", fmt.Errorf("snapshot: diff ID %q: %w", diffID, err)
	}
	if parent == "" {
		return d, nil
	}
	p, err := NormalizeDigest(parent)
	if err != nil {
		return "", fmt.Errorf("snapshot: parent chain ID %q: %w", parent, err)
	}
	sum := sha256.Sum256([]byte(p + " " + d))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ChainIDs computes the chain ID of every prefix of diffIDs, base layer first.
// The returned slice has the same length as diffIDs and its last element is the
// chain ID of the whole image.
func ChainIDs(diffIDs []string) ([]string, error) {
	out := make([]string, 0, len(diffIDs))
	prev := ""
	for i, d := range diffIDs {
		c, err := ChainID(prev, d)
		if err != nil {
			return nil, fmt.Errorf("snapshot: layer %d: %w", i, err)
		}
		out = append(out, c)
		prev = c
	}
	return out, nil
}

// TopChainID returns the chain ID of the topmost layer, which is the chain ID
// of the image as a whole. An empty diffIDs yields an empty chain ID and no
// error, because an image with no layers has no chain.
func TopChainID(diffIDs []string) (string, error) {
	chain, err := ChainIDs(diffIDs)
	if err != nil {
		return "", err
	}
	if len(chain) == 0 {
		return "", nil
	}
	return chain[len(chain)-1], nil
}

// NormalizeDigest accepts a sha256 digest with or without its algorithm prefix
// and returns the canonical "sha256:<64 lowercase hex>" form.
func NormalizeDigest(id string) (string, error) {
	h, err := digestHex(id)
	if err != nil {
		return "", err
	}
	return "sha256:" + h, nil
}

// digestHex returns the bare 64-character hex of a sha256 digest.
func digestHex(id string) (string, error) {
	s := strings.TrimPrefix(id, "sha256:")
	if s == id && strings.Contains(id, ":") {
		return "", fmt.Errorf("%w: %q uses an algorithm hull does not implement (only sha256)", ErrInvalidChainID, id)
	}
	if len(s) != 64 {
		return "", fmt.Errorf("%w: %q has %d hex characters, want 64", ErrInvalidChainID, id, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", fmt.Errorf("%w: %q contains %q, which is not lowercase hex", ErrInvalidChainID, id, string(c))
		}
	}
	return s, nil
}

// chainHex is digestHex with a chain-ID-flavoured error message.
func chainHex(chainID string) (string, error) {
	h, err := digestHex(chainID)
	if err != nil {
		return "", fmt.Errorf("snapshot: chain ID: %w", err)
	}
	return h, nil
}

// ---------- names and option strings ----------

// validateName checks that s is usable as one path component under the
// snapshotter root. Container IDs and checkpoint names reach this package from
// the API, so they are validated rather than trusted.
func validateName(kind, s string) error {
	if s == "" {
		return fmt.Errorf("snapshot: empty %s", kind)
	}
	if len(s) > 128 {
		return fmt.Errorf("snapshot: %s %q is %d bytes, the limit is 128", kind, s, len(s))
	}
	if s == "." || s == ".." {
		return fmt.Errorf("snapshot: %s %q is not a usable directory name", kind, s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.'
		if !ok {
			return fmt.Errorf("snapshot: %s %q contains %q; only letters, digits, '-', '_' and '.' are allowed",
				kind, s, string(c))
		}
	}
	return nil
}

// linkAlphabet is the character set short link names are drawn from. Lowercase
// comes first so the common case reads easily in /proc/self/mountinfo.
const linkAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// linkBase is the size of linkAlphabet.
const linkBase = len(linkAlphabet)

// twoCharNames is how many two-character names exist.
const twoCharNames = 62 * 62

// threeCharNames is how many three-character names exist.
const threeCharNames = 62 * 62 * 62

// nameForIndex maps a dense non-negative index onto a short link name. The
// first 3844 indexes are two characters, the next 238328 are three and the rest
// are four, so a realistic host never spends more than three characters per
// layer in a lowerdir list.
func nameForIndex(i int) string {
	if i < 0 {
		i = -i
	}
	width := 2
	switch {
	case i < twoCharNames:
	case i < twoCharNames+threeCharNames:
		i -= twoCharNames
		width = 3
	default:
		i -= twoCharNames + threeCharNames
		i %= linkBase * linkBase * linkBase * linkBase
		width = 4
	}
	buf := make([]byte, width)
	for p := width - 1; p >= 0; p-- {
		buf[p] = linkAlphabet[i%linkBase]
		i /= linkBase
	}
	return string(buf)
}

// linkStartIndex picks the first candidate name for a chain ID. Deriving it
// from the chain ID rather than from a shared counter means two processes
// allocating different layers rarely collide, so allocation is usually a single
// symlink(2) call.
func linkStartIndex(chainID string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(chainID))
	return int(h.Sum32() % uint32(twoCharNames))
}

// optionSeparators are the characters that would be misread inside a mount
// option string. A path containing one cannot be used as a lowerdir.
const optionSeparators = ":,\n\\\"="

// checkOptionPath rejects a path that cannot appear in a mount option string.
func checkOptionPath(what, p string) error {
	if p == "" {
		return fmt.Errorf("snapshot: empty %s path", what)
	}
	if i := strings.IndexAny(p, optionSeparators); i >= 0 {
		return fmt.Errorf("snapshot: %s path %q contains %q, which cannot be expressed in an overlay "+
			"mount option string; move hull's root somewhere without it", what, p, string(p[i]))
	}
	return nil
}

// buildOverlayOptions renders the overlay mount option string.
//
// lowers must be ordered top-to-bottom, which is overlayfs's own lowerdir
// order: the newest layer first. upper and work are empty for a read-only
// mount, which overlayfs only accepts with two or more lower layers.
//
// redirect_dir, metacopy and index are always spelled out rather than left to
// the module defaults, because the WSL 6.6 kernel config sets
// OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=y, which would silently change what a diff
// of the upperdir means.
func buildOverlayOptions(lowers []string, upper, work string, userxattr bool) (string, error) {
	if len(lowers) == 0 {
		return "", errors.New("snapshot: an overlay mount needs at least one lower layer")
	}
	if upper == "" && len(lowers) < 2 {
		return "", errors.New("snapshot: a read-only overlay mount needs at least two lower layers")
	}
	for _, l := range lowers {
		if err := checkOptionPath("lowerdir", l); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	b.WriteString("lowerdir=")
	b.WriteString(strings.Join(lowers, ":"))
	if upper != "" {
		if err := checkOptionPath("upperdir", upper); err != nil {
			return "", err
		}
		if err := checkOptionPath("workdir", work); err != nil {
			return "", err
		}
		b.WriteString(",upperdir=")
		b.WriteString(upper)
		b.WriteString(",workdir=")
		b.WriteString(work)
	}
	b.WriteString(",redirect_dir=off,metacopy=off,index=off")
	if userxattr {
		b.WriteString(",userxattr")
	}
	return b.String(), nil
}

// fitsOnePage reports whether an option string is short enough for mount(2).
func fitsOnePage(opts string) bool { return len(opts) <= MaxMountOptions }
