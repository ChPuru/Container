// Package layer applies and produces OCI/Docker filesystem layer tars.
//
// Layer tars are attacker-controlled data: a pulled image is nothing but a
// sequence of them. Every path in a layer is therefore resolved fd-relative,
// one component at a time, from a directory file descriptor anchored at the
// destination, using openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS|
// RESOLVE_NO_SYMLINKS) where the kernel provides it and an O_NOFOLLOW openat
// walk where it does not. No container-controlled path is ever handed to
// filepath.Join plus os.Open.
//
// Apply consumes a layer, Diff produces one from an overlayfs upperdir. Both
// speak the AUFS whiteout convention that OCI layers use on the wire:
//
//	.wh.<name>      delete <name> from the merged view
//	.wh..wh..opq    the containing directory is opaque: everything the lower
//	                layers put in it disappears
//	.wh..wh.*       AUFS bookkeeping, ignored
//
// On disk, overlayfs instead represents a deletion as a character device with
// device number 0:0 and an opaque directory as the xattr trusted.overlay.opaque
// (user.overlay.opaque when the overlay is rootless); Diff translates between
// the two.
package layer

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Media types hull understands for a layer blob.
const (
	// MediaTypeTar is an uncompressed OCI layer.
	MediaTypeTar = "application/vnd.oci.image.layer.v1.tar"
	// MediaTypeTarGzip is a gzip-compressed OCI layer.
	MediaTypeTarGzip = MediaTypeTar + "+gzip"
	// MediaTypeTarZstd is a zstd-compressed OCI layer. hull can detect but not
	// decompress these; see ErrZstdUnsupported.
	MediaTypeTarZstd = MediaTypeTar + "+zstd"
	// MediaTypeDockerTar is a Docker schema2 uncompressed layer.
	MediaTypeDockerTar = "application/vnd.docker.image.rootfs.diff.tar"
	// MediaTypeDockerTarGzip is a Docker schema2 gzip-compressed layer.
	MediaTypeDockerTarGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	// MediaTypeDockerForeignTarGzip is a Docker foreign (non-distributable) layer.
	MediaTypeDockerForeignTarGzip = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
)

// AUFS whiteout markers as they appear inside a layer tar.
const (
	// WhiteoutPrefix marks a deleted path: ".wh.<name>".
	WhiteoutPrefix = ".wh."
	// WhiteoutMetaPrefix marks AUFS bookkeeping entries, which are ignored.
	WhiteoutMetaPrefix = WhiteoutPrefix + WhiteoutPrefix
	// WhiteoutOpaqueDir marks the containing directory as opaque.
	WhiteoutOpaqueDir = WhiteoutMetaPrefix + ".opq"
	// WhiteoutLinkDir is the AUFS hardlink bookkeeping directory.
	WhiteoutLinkDir = WhiteoutMetaPrefix + "plnk"
)

// Overlayfs xattr names used to mark an opaque directory on disk.
const (
	// OpaqueXattrTrusted is the privileged overlayfs opaque marker.
	OpaqueXattrTrusted = "trusted.overlay.opaque"
	// OpaqueXattrUser is the rootless overlayfs opaque marker.
	OpaqueXattrUser = "user.overlay.opaque"
)

// Default safety caps applied when ApplyOptions leaves them at zero.
const (
	// DefaultMaxEntries is the default cap on tar entries in one layer.
	DefaultMaxEntries = 2_000_000
	// DefaultMaxBytes is the default cap on uncompressed bytes in one layer.
	DefaultMaxBytes int64 = 64 << 30
)

// maxWarnings bounds how many warnings a single Result will retain.
const maxWarnings = 64

// Errors returned by this package. All are wrapped with %w, so callers can
// match them with errors.Is.
var (
	// ErrPathEscape means an entry tried to leave the destination directory,
	// by an absolute path, by "..", or by traversing a symlink.
	ErrPathEscape = errors.New("layer: path escapes destination")
	// ErrInvalidPath means an entry name is not usable at all: it is empty,
	// it is ".", or it contains a NUL byte.
	ErrInvalidPath = errors.New("layer: invalid entry path")
	// ErrTooManyEntries means the layer exceeded ApplyOptions.MaxEntries.
	ErrTooManyEntries = errors.New("layer: too many tar entries")
	// ErrTooLarge means the layer exceeded ApplyOptions.MaxBytes.
	ErrTooLarge = errors.New("layer: layer too large")
	// ErrZstdUnsupported means the blob is zstd-compressed. The Go standard
	// library cannot decompress zstd and hull adds no module for it, so the
	// caller must obtain a gzip or uncompressed variant of the layer.
	ErrZstdUnsupported = errors.New("layer: zstd-compressed layers are not supported (re-pull or convert the image to tar+gzip)")
	// ErrUnsupportedCompression means the blob uses a compression hull does
	// not implement (xz, bzip2, ...).
	ErrUnsupportedCompression = errors.New("layer: unsupported compression")
	// ErrUnsupportedPlatform means this build of hull cannot apply layers,
	// because layer application is implemented with Linux syscalls.
	ErrUnsupportedPlatform = errors.New("layer: layer operations require Linux")
)

// ApplyOptions tunes how a layer is unpacked.
type ApplyOptions struct {
	// UIDOffset is added to every entry's uid, for user-namespace remapping.
	UIDOffset int
	// GIDOffset is added to every entry's gid, for user-namespace remapping.
	GIDOffset int
	// NoSameOwner ignores uid/gid entirely; every file ends up owned by the
	// caller. This is the right setting for rootless extraction.
	NoSameOwner bool
	// Filter, when non-nil, is called for every entry with its name already
	// normalised to a destination-relative path. Returning false skips the
	// entry, including any whiteout effect it would have had.
	Filter func(hdr *tar.Header) bool
	// MaxEntries caps the number of tar entries. Zero means DefaultMaxEntries;
	// a negative value disables the cap.
	MaxEntries int
	// MaxBytes caps the uncompressed size of the tar stream. Zero means
	// DefaultMaxBytes; a negative value disables the cap.
	MaxBytes int64
	// Logf, when non-nil, receives non-fatal fidelity warnings (an xattr that
	// could not be set, a device node skipped for lack of privilege).
	Logf func(format string, args ...any)
}

// withDefaults returns a copy of o with the zero-valued caps filled in.
func (o ApplyOptions) withDefaults() ApplyOptions {
	if o.MaxEntries == 0 {
		o.MaxEntries = DefaultMaxEntries
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	return o
}

// Result reports what an Apply or Diff did.
type Result struct {
	// Size is the number of uncompressed tar bytes read (Apply) or written
	// (Diff). This is the value an image config's layer size refers to.
	Size int64
	// Files is the number of entries materialised, whiteouts excluded.
	Files int
	// Whiteouts is the number of deletion and opaque markers processed.
	Whiteouts int
	// DiffID is the sha256 of the uncompressed tar stream, in
	// "sha256:<hex>" form, ready to compare against rootfs.diff_ids.
	DiffID string
	// Entries is the total number of tar headers seen.
	Entries int
	// Skipped is the number of entries deliberately not materialised: filtered
	// out, AUFS bookkeeping, or device nodes that needed privilege hull did
	// not have.
	Skipped int
	// Warnings holds up to 64 non-fatal fidelity complaints.
	Warnings []string
}

// Compression identifies the wrapper around a tar stream.
type Compression int

// Recognised compression wrappers.
const (
	// CompressionNone is a bare tar stream.
	CompressionNone Compression = iota
	// CompressionGzip is a gzip-wrapped tar stream.
	CompressionGzip
	// CompressionZstd is a zstd-wrapped tar stream, which hull cannot read.
	CompressionZstd
	// CompressionXz is an xz-wrapped tar stream, which hull cannot read.
	CompressionXz
	// CompressionBzip2 is a bzip2-wrapped tar stream, which hull cannot read.
	CompressionBzip2
)

// String names the compression wrapper.
func (c Compression) String() string {
	switch c {
	case CompressionGzip:
		return "gzip"
	case CompressionZstd:
		return "zstd"
	case CompressionXz:
		return "xz"
	case CompressionBzip2:
		return "bzip2"
	default:
		return "none"
	}
}

// DetectCompression sniffs the magic bytes at the head of br without consuming
// them. A stream too short to carry any known magic is reported as
// CompressionNone, which lets a zero-length or tiny tar through unharmed.
func DetectCompression(br *bufio.Reader) (Compression, error) {
	magic, err := br.Peek(6)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return CompressionNone, fmt.Errorf("layer: sniff compression: %w", err)
	}
	switch {
	case len(magic) >= 2 && magic[0] == 0x1F && magic[1] == 0x8B:
		return CompressionGzip, nil
	case len(magic) >= 4 && magic[0] == 0x28 && magic[1] == 0xB5 && magic[2] == 0x2F && magic[3] == 0xFD:
		return CompressionZstd, nil
	case len(magic) >= 6 && magic[0] == 0xFD && magic[1] == '7' && magic[2] == 'z' && magic[3] == 'X' && magic[4] == 'Z' && magic[5] == 0x00:
		return CompressionXz, nil
	case len(magic) >= 3 && magic[0] == 'B' && magic[1] == 'Z' && magic[2] == 'h':
		return CompressionBzip2, nil
	default:
		return CompressionNone, nil
	}
}

// ApplyCompressed unpacks a possibly compressed layer blob into dest.
//
// The magic bytes at the head of the stream decide how it is read, so a blob
// whose media type lies about its compression is still handled correctly; the
// media type is only consulted when the stream carries no magic at all, and to
// make error messages actionable. Gzip is decompressed in-process; zstd is
// detected and reported as ErrZstdUnsupported rather than being fed to the tar
// reader as garbage.
//
// The returned Result.DiffID is the digest of the *uncompressed* stream.
func ApplyCompressed(ctx context.Context, dest string, r io.Reader, mediaType string, opts ApplyOptions) (Result, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	c, err := DetectCompression(br)
	if err != nil {
		return Result{}, err
	}
	switch c {
	case CompressionGzip:
		zr, gerr := gzip.NewReader(br)
		if gerr != nil {
			return Result{}, fmt.Errorf("layer: open gzip stream (media type %q): %w", mediaType, gerr)
		}
		defer zr.Close()
		return Apply(ctx, dest, zr, opts)
	case CompressionZstd:
		return Result{}, fmt.Errorf("layer: blob with media type %q: %w", mediaType, ErrZstdUnsupported)
	case CompressionXz, CompressionBzip2:
		return Result{}, fmt.Errorf("layer: blob with media type %q is %s-compressed: %w", mediaType, c, ErrUnsupportedCompression)
	default:
		if strings.HasSuffix(mediaType, "+zstd") {
			return Result{}, fmt.Errorf("layer: blob with media type %q: %w", mediaType, ErrZstdUnsupported)
		}
		return Apply(ctx, dest, br, opts)
	}
}

// cleanName normalises a tar entry name to a destination-relative path.
//
// It returns ErrPathEscape for absolute paths and for any ".." component, and
// ErrInvalidPath for a name containing a NUL byte. A name that reduces to
// nothing ("." or "./") yields an empty string and no error; callers decide
// what that means for the entry type at hand.
func cleanName(name string) (string, error) {
	if strings.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("%w: NUL byte in %q", ErrInvalidPath, name)
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: absolute path %q", ErrPathEscape, name)
	}
	parts := strings.Split(name, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		switch p {
		case "", ".":
			continue
		case "..":
			return "", fmt.Errorf("%w: %q contains a parent reference", ErrPathEscape, name)
		}
		out = append(out, p)
	}
	return strings.Join(out, "/"), nil
}

// splitPath splits a cleaned relative path into its directory and base name.
func splitPath(rel string) (dir, base string) {
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		return rel[:i], rel[i+1:]
	}
	return "", rel
}

// xattrPAXPrefix is the PAX record prefix star/GNU tar use for xattrs.
const xattrPAXPrefix = "SCHILY.xattr."

// xattrsOf extracts the SCHILY.xattr.* PAX records from a header.
func xattrsOf(hdr *tar.Header) map[string]string {
	var out map[string]string
	for k, v := range hdr.PAXRecords {
		if !strings.HasPrefix(k, xattrPAXPrefix) {
			continue
		}
		if out == nil {
			out = make(map[string]string, 4)
		}
		out[strings.TrimPrefix(k, xattrPAXPrefix)] = v
	}
	return out
}

// ctxErr reports whether ctx has been cancelled.
func ctxErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// countingReader counts bytes read and enforces a ceiling on the total.
type countingReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.max > 0 && c.n > c.max {
		return n, fmt.Errorf("%w: exceeded %d uncompressed bytes", ErrTooLarge, c.max)
	}
	return n, err
}

// countingWriter counts bytes written.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
