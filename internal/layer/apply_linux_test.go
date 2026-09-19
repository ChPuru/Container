//go:build linux

package layer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// tarEntry is one entry of a golden tar built in-test.
type tarEntry struct {
	hdr  tar.Header
	body string
}

// buildTar serialises entries into an uncompressed tar.
func buildTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range entries {
		e := entries[i]
		h := e.hdr
		if h.Format == tar.FormatUnknown {
			h.Format = tar.FormatPAX
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if h.ModTime.IsZero() {
			h.ModTime = time.Unix(1600000000, 0)
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("write header %q: %v", h.Name, err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %q: %v", h.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func lstat(t *testing.T, path string) *unix.Stat_t {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return &st
}

func TestApplyGoldenLayer(t *testing.T) {
	mtime := time.Unix(1600000000, 0)
	dirTime := time.Unix(1500000000, 0)

	blob := buildTar(t,
		tarEntry{hdr: tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755}},
		tarEntry{hdr: tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: dirTime}},
		tarEntry{hdr: tar.Header{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: dirTime}},
		tarEntry{hdr: tar.Header{Name: "usr/bin/tool", Typeflag: tar.TypeReg, Mode: 0o755, ModTime: mtime}, body: "#!/bin/sh\n"},
		tarEntry{hdr: tar.Header{Name: "usr/bin/suid", Typeflag: tar.TypeReg, Mode: 0o4755, ModTime: mtime}, body: "setuid\n"},
		tarEntry{hdr: tar.Header{Name: "usr/bin/sticky/", Typeflag: tar.TypeDir, Mode: 0o1777, ModTime: dirTime}},
		tarEntry{hdr: tar.Header{Name: "usr/bin/hard", Typeflag: tar.TypeLink, Linkname: "usr/bin/tool", Mode: 0o755}},
		tarEntry{hdr: tar.Header{Name: "usr/bin/link", Typeflag: tar.TypeSymlink, Linkname: "tool", Mode: 0o777}},
		tarEntry{hdr: tar.Header{Name: "var/run/pipe", Typeflag: tar.TypeFifo, Mode: 0o644}},
		tarEntry{hdr: tar.Header{
			Name: "etc/conf", Typeflag: tar.TypeReg, Mode: 0o600, ModTime: mtime,
			PAXRecords: map[string]string{xattrPAXPrefix + "user.hull": "v1"},
		}, body: "k=v\n"},
	)

	dest := t.TempDir()
	res, err := Apply(context.Background(), dest, bytes.NewReader(blob), ApplyOptions{NoSameOwner: true})
	if err != nil {
		t.Fatalf("Apply: %v (warnings %v)", err, res.Warnings)
	}

	sum := sha256.Sum256(blob)
	if want := "sha256:" + hex.EncodeToString(sum[:]); res.DiffID != want {
		t.Fatalf("DiffID = %s, want %s", res.DiffID, want)
	}
	if res.Size != int64(len(blob)) {
		t.Fatalf("Size = %d, want %d", res.Size, len(blob))
	}
	if res.Entries != 10 {
		t.Fatalf("Entries = %d, want 10", res.Entries)
	}
	if res.Whiteouts != 0 {
		t.Fatalf("Whiteouts = %d, want 0", res.Whiteouts)
	}
	if res.Skipped != 1 { // the "./" root entry
		t.Fatalf("Skipped = %d, want 1", res.Skipped)
	}

	// File content and mode, including setuid.
	got, err := os.ReadFile(filepath.Join(dest, "usr/bin/tool"))
	if err != nil || string(got) != "#!/bin/sh\n" {
		t.Fatalf("tool content = %q, err %v", got, err)
	}
	if st := lstat(t, filepath.Join(dest, "usr/bin/suid")); st.Mode&0o7777 != 0o4755 {
		t.Fatalf("suid mode = %#o, want %#o", st.Mode&0o7777, 0o4755)
	}
	if st := lstat(t, filepath.Join(dest, "usr/bin/sticky")); st.Mode&0o7777 != 0o1777 {
		t.Fatalf("sticky mode = %#o, want %#o", st.Mode&0o7777, 0o1777)
	}

	// Hardlink shares the inode; the symlink is a symlink, not its target.
	a := lstat(t, filepath.Join(dest, "usr/bin/tool"))
	b := lstat(t, filepath.Join(dest, "usr/bin/hard"))
	if a.Ino != b.Ino || b.Nlink != 2 {
		t.Fatalf("hardlink: ino %d vs %d, nlink %d", a.Ino, b.Ino, b.Nlink)
	}
	target, err := os.Readlink(filepath.Join(dest, "usr/bin/link"))
	if err != nil || target != "tool" {
		t.Fatalf("readlink = %q, err %v", target, err)
	}

	// FIFO.
	if st := lstat(t, filepath.Join(dest, "var/run/pipe")); st.Mode&unix.S_IFMT != unix.S_IFIFO {
		t.Fatalf("pipe is not a FIFO: mode %#o", st.Mode)
	}

	// mtime survives, and directory mtimes are not clobbered by their children.
	if st := lstat(t, filepath.Join(dest, "usr/bin/tool")); st.Mtim.Sec != mtime.Unix() {
		t.Fatalf("file mtime = %d, want %d", st.Mtim.Sec, mtime.Unix())
	}
	if st := lstat(t, filepath.Join(dest, "usr/bin")); st.Mtim.Sec != dirTime.Unix() {
		t.Fatalf("directory mtime = %d, want %d (children clobbered it)", st.Mtim.Sec, dirTime.Unix())
	}

	// xattrs are best-effort: if the filesystem supports them they must be set.
	buf := make([]byte, 16)
	n, xerr := unix.Lgetxattr(filepath.Join(dest, "etc/conf"), "user.hull", buf)
	switch {
	case xerr == nil:
		if string(buf[:n]) != "v1" {
			t.Fatalf("user.hull = %q, want %q", buf[:n], "v1")
		}
	case errors.Is(xerr, unix.ENOTSUP), errors.Is(xerr, unix.EOPNOTSUPP):
		t.Logf("filesystem does not support user xattrs; skipped that check")
	default:
		t.Fatalf("getxattr: %v", xerr)
	}
}

func TestApplyWhiteouts(t *testing.T) {
	dest := t.TempDir()
	// Pre-existing content, as if a lower layer had already been applied here.
	mustMkdirAll(t, filepath.Join(dest, "opq/keep/deep"))
	mustWrite(t, filepath.Join(dest, "opq/keep/deep/file"), "old")
	mustWrite(t, filepath.Join(dest, "opq/gone"), "old")
	mustMkdirAll(t, filepath.Join(dest, "d"))
	mustWrite(t, filepath.Join(dest, "d/victim"), "old")
	mustMkdirAll(t, filepath.Join(dest, "d/victimdir/sub"))
	mustWrite(t, filepath.Join(dest, "d/victimdir/sub/f"), "old")
	mustWrite(t, filepath.Join(dest, "d/survivor"), "old")

	blob := buildTar(t,
		tarEntry{hdr: tar.Header{Name: "d/" + WhiteoutPrefix + "victim", Typeflag: tar.TypeReg, Mode: 0}},
		tarEntry{hdr: tar.Header{Name: "d/" + WhiteoutPrefix + "victimdir", Typeflag: tar.TypeReg, Mode: 0}},
		tarEntry{hdr: tar.Header{Name: "d/" + WhiteoutLinkDir, Typeflag: tar.TypeReg, Mode: 0}},
		tarEntry{hdr: tar.Header{Name: "d/" + WhiteoutMetaPrefix + "aufs", Typeflag: tar.TypeReg, Mode: 0}},
		tarEntry{hdr: tar.Header{Name: "opq/" + WhiteoutOpaqueDir, Typeflag: tar.TypeReg, Mode: 0}},
		tarEntry{hdr: tar.Header{Name: "opq/fresh", Typeflag: tar.TypeReg, Mode: 0o644}, body: "new"},
	)

	res, err := Apply(context.Background(), dest, bytes.NewReader(blob), ApplyOptions{NoSameOwner: true})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Whiteouts != 3 {
		t.Fatalf("Whiteouts = %d, want 3", res.Whiteouts)
	}
	if res.Skipped != 2 {
		t.Fatalf("Skipped = %d, want 2 (aufs bookkeeping)", res.Skipped)
	}

	assertMissing(t, filepath.Join(dest, "d/victim"))
	assertMissing(t, filepath.Join(dest, "d/victimdir"))
	assertMissing(t, filepath.Join(dest, "d/"+WhiteoutPrefix+"victim"))
	assertMissing(t, filepath.Join(dest, "d/"+WhiteoutLinkDir))
	assertExists(t, filepath.Join(dest, "d/survivor"))

	// The opaque marker clears the directory but leaves it, and entries that
	// come after it in the stream survive.
	assertMissing(t, filepath.Join(dest, "opq/keep"))
	assertMissing(t, filepath.Join(dest, "opq/gone"))
	assertMissing(t, filepath.Join(dest, "opq/"+WhiteoutOpaqueDir))
	assertExists(t, filepath.Join(dest, "opq/fresh"))
}

func TestApplyRejectsUnsafeEntries(t *testing.T) {
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret"), "do not touch")

	tests := []struct {
		name    string
		entries []tarEntry
		wantErr error
	}{
		{
			name:    "parent escape",
			entries: []tarEntry{{hdr: tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644}, body: "x"}},
			wantErr: ErrPathEscape,
		},
		{
			name:    "buried parent escape",
			entries: []tarEntry{{hdr: tar.Header{Name: "a/b/../../../escape", Typeflag: tar.TypeReg, Mode: 0o644}, body: "x"}},
			wantErr: ErrPathEscape,
		},
		{
			name:    "absolute path",
			entries: []tarEntry{{hdr: tar.Header{Name: "/etc/shadow", Typeflag: tar.TypeReg, Mode: 0o644}, body: "x"}},
			wantErr: ErrPathEscape,
		},
		{
			// A NUL byte in a name cannot be expressed by archive/tar at all
			// (the writer refuses the PAX record and ustar truncates at the
			// NUL), so that defence is exercised in TestCleanName instead.
			name:    "dot dot as the whole name",
			entries: []tarEntry{{hdr: tar.Header{Name: "..", Typeflag: tar.TypeDir, Mode: 0o755}}},
			wantErr: ErrPathEscape,
		},
		{
			name:    "dot as a regular file",
			entries: []tarEntry{{hdr: tar.Header{Name: ".", Typeflag: tar.TypeReg, Mode: 0o644}, body: "x"}},
			wantErr: ErrInvalidPath,
		},
		{
			name: "symlink traversal",
			entries: []tarEntry{
				{hdr: tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0o777}},
				{hdr: tar.Header{Name: "link/secret", Typeflag: tar.TypeReg, Mode: 0o644}, body: "pwned"},
			},
			wantErr: ErrPathEscape,
		},
		{
			name: "symlink to root traversal",
			entries: []tarEntry{
				{hdr: tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/", Mode: 0o777}},
				{hdr: tar.Header{Name: "link/etc/passwd", Typeflag: tar.TypeReg, Mode: 0o644}, body: "pwned"},
			},
			wantErr: ErrPathEscape,
		},
		{
			name: "hardlink target escape",
			entries: []tarEntry{
				{hdr: tar.Header{Name: "evil", Typeflag: tar.TypeLink, Linkname: "../" + filepath.Base(outside) + "/secret", Mode: 0o644}},
			},
			wantErr: ErrPathEscape,
		},
		{
			name: "hardlink through a symlink",
			entries: []tarEntry{
				{hdr: tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0o777}},
				{hdr: tar.Header{Name: "evil", Typeflag: tar.TypeLink, Linkname: "link/secret", Mode: 0o644}},
			},
			wantErr: ErrPathEscape,
		},
		{
			name:    "whiteout of a path",
			entries: []tarEntry{{hdr: tar.Header{Name: WhiteoutPrefix + ".", Typeflag: tar.TypeReg, Mode: 0}}},
			wantErr: ErrInvalidPath,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dest := t.TempDir()
			blob := buildTar(t, tc.entries...)
			_, err := Apply(context.Background(), dest, bytes.NewReader(blob), ApplyOptions{NoSameOwner: true})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Apply error = %v, want %v", err, tc.wantErr)
			}
			// Nothing may have leaked outside the destination.
			got, rerr := os.ReadFile(filepath.Join(outside, "secret"))
			if rerr != nil || string(got) != "do not touch" {
				t.Fatalf("outside file was modified: %q err %v", got, rerr)
			}
			if entries, _ := os.ReadDir(outside); len(entries) != 1 {
				t.Fatalf("outside directory gained entries: %d", len(entries))
			}
			assertMissing(t, "/etc/passwd.hull-test")
		})
	}
}

func TestApplyLimits(t *testing.T) {
	t.Run("max entries", func(t *testing.T) {
		var entries []tarEntry
		for i := 0; i < 20; i++ {
			entries = append(entries, tarEntry{
				hdr:  tar.Header{Name: fmt.Sprintf("f%02d", i), Typeflag: tar.TypeReg, Mode: 0o644},
				body: "x",
			})
		}
		blob := buildTar(t, entries...)
		res, err := Apply(context.Background(), t.TempDir(), bytes.NewReader(blob),
			ApplyOptions{NoSameOwner: true, MaxEntries: 5})
		if !errors.Is(err, ErrTooManyEntries) {
			t.Fatalf("error = %v, want ErrTooManyEntries", err)
		}
		if res.Entries != 6 {
			t.Fatalf("stopped after %d entries, want 6", res.Entries)
		}
	})

	t.Run("max bytes", func(t *testing.T) {
		blob := buildTar(t, tarEntry{
			hdr:  tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0o644},
			body: strings.Repeat("A", 64<<10),
		})
		_, err := Apply(context.Background(), t.TempDir(), bytes.NewReader(blob),
			ApplyOptions{NoSameOwner: true, MaxBytes: 4096})
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge", err)
		}
	})

	t.Run("caps disabled", func(t *testing.T) {
		blob := buildTar(t, tarEntry{hdr: tar.Header{Name: "f", Typeflag: tar.TypeReg, Mode: 0o644}, body: "x"})
		if _, err := Apply(context.Background(), t.TempDir(), bytes.NewReader(blob),
			ApplyOptions{NoSameOwner: true, MaxEntries: -1, MaxBytes: -1}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	})
}

func TestApplyFilter(t *testing.T) {
	blob := buildTar(t,
		tarEntry{hdr: tar.Header{Name: "keep", Typeflag: tar.TypeReg, Mode: 0o644}, body: "a"},
		tarEntry{hdr: tar.Header{Name: "drop", Typeflag: tar.TypeReg, Mode: 0o644}, body: "b"},
		tarEntry{hdr: tar.Header{Name: "sub/", Typeflag: tar.TypeDir, Mode: 0o755}},
	)
	dest := t.TempDir()
	var seen []string
	res, err := Apply(context.Background(), dest, bytes.NewReader(blob), ApplyOptions{
		NoSameOwner: true,
		Filter: func(hdr *tar.Header) bool {
			seen = append(seen, hdr.Name)
			return hdr.Name != "drop"
		},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Skipped != 1 || res.Files != 2 {
		t.Fatalf("Skipped = %d, Files = %d, want 1 and 2", res.Skipped, res.Files)
	}
	want := []string{"keep", "drop", "sub/"}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("filter saw %v, want %v", seen, want)
	}
	assertExists(t, filepath.Join(dest, "keep"))
	assertMissing(t, filepath.Join(dest, "drop"))
}

func TestApplyOverwritesExistingEntries(t *testing.T) {
	dest := t.TempDir()
	// A symlink pointing outside must be replaced, not written through.
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret"), "do not touch")
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dest, "f")); err != nil {
		t.Fatal(err)
	}
	mustMkdirAll(t, filepath.Join(dest, "dir/sub"))
	mustWrite(t, filepath.Join(dest, "dir/sub/x"), "old")

	blob := buildTar(t,
		tarEntry{hdr: tar.Header{Name: "f", Typeflag: tar.TypeReg, Mode: 0o644}, body: "new"},
		tarEntry{hdr: tar.Header{Name: "dir", Typeflag: tar.TypeReg, Mode: 0o644}, body: "now a file"},
	)
	if _, err := Apply(context.Background(), dest, bytes.NewReader(blob), ApplyOptions{NoSameOwner: true}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(outside, "secret")); string(got) != "do not touch" {
		t.Fatalf("wrote through a symlink: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "f")); string(got) != "new" {
		t.Fatalf("f = %q, want %q", got, "new")
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "dir")); string(got) != "now a file" {
		t.Fatalf("dir = %q, want %q", got, "now a file")
	}
}

func TestApplyReplacesFileWithDirectoryOnTheWay(t *testing.T) {
	dest := t.TempDir()
	mustWrite(t, filepath.Join(dest, "a"), "file")
	blob := buildTar(t, tarEntry{hdr: tar.Header{Name: "a/b/c", Typeflag: tar.TypeReg, Mode: 0o644}, body: "deep"})
	if _, err := Apply(context.Background(), dest, bytes.NewReader(blob), ApplyOptions{NoSameOwner: true}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "a/b/c")); string(got) != "deep" {
		t.Fatalf("a/b/c = %q", got)
	}
}

func TestApplyUIDOffsets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	blob := buildTar(t, tarEntry{hdr: tar.Header{
		Name: "f", Typeflag: tar.TypeReg, Mode: 0o644, Uid: 1000, Gid: 1000,
	}, body: "x"})
	dest := t.TempDir()
	if _, err := Apply(context.Background(), dest, bytes.NewReader(blob),
		ApplyOptions{UIDOffset: 100000, GIDOffset: 100000}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	st := lstat(t, filepath.Join(dest, "f"))
	if st.Uid != 101000 || st.Gid != 101000 {
		t.Fatalf("uid/gid = %d/%d, want 101000/101000", st.Uid, st.Gid)
	}
}

func TestApplyNegativeOffsetIsRejected(t *testing.T) {
	blob := buildTar(t, tarEntry{hdr: tar.Header{Name: "f", Typeflag: tar.TypeReg, Mode: 0o644}, body: "x"})
	_, err := Apply(context.Background(), t.TempDir(), bytes.NewReader(blob), ApplyOptions{UIDOffset: -5})
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("error = %v, want an out-of-range complaint", err)
	}
}

func TestApplyDeviceNodesWithoutPrivilege(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test covers the unprivileged path")
	}
	blob := buildTar(t, tarEntry{hdr: tar.Header{
		Name: "dev/null", Typeflag: tar.TypeChar, Mode: 0o666, Devmajor: 1, Devminor: 3,
	}})
	dest := t.TempDir()
	res, err := Apply(context.Background(), dest, bytes.NewReader(blob), ApplyOptions{NoSameOwner: true})
	if err != nil {
		t.Fatalf("Apply must not fail on an unprivileged device node: %v", err)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", res.Skipped)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("skipping a device node must produce a warning, not silence")
	}
	assertMissing(t, filepath.Join(dest, "dev/null"))
}

func TestApplyDeviceNodesAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	blob := buildTar(t, tarEntry{hdr: tar.Header{
		Name: "dev/null", Typeflag: tar.TypeChar, Mode: 0o666, Devmajor: 1, Devminor: 3,
	}})
	dest := t.TempDir()
	res, err := Apply(context.Background(), dest, bytes.NewReader(blob), ApplyOptions{})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Skipped != 0 {
		t.Skipf("kernel refused mknod (%v); nothing to assert", res.Warnings)
	}
	st := lstat(t, filepath.Join(dest, "dev/null"))
	if st.Mode&unix.S_IFMT != unix.S_IFCHR {
		t.Fatalf("dev/null is not a character device: %#o", st.Mode)
	}
	if unix.Major(uint64(st.Rdev)) != 1 || unix.Minor(uint64(st.Rdev)) != 3 {
		t.Fatalf("rdev = %d:%d, want 1:3", unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)))
	}
}

func TestApplyContextCancellation(t *testing.T) {
	blob := buildTar(t, tarEntry{hdr: tar.Header{Name: "f", Typeflag: tar.TypeReg, Mode: 0o644}, body: "x"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Apply(ctx, t.TempDir(), bytes.NewReader(blob), ApplyOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestApplyCompressed(t *testing.T) {
	plain := buildTar(t, tarEntry{hdr: tar.Header{Name: "f", Typeflag: tar.TypeReg, Mode: 0o644}, body: "hello"})
	sum := sha256.Sum256(plain)
	wantDiffID := "sha256:" + hex.EncodeToString(sum[:])

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		blob      []byte
		mediaType string
		wantErr   error
	}{
		{name: "plain tar", blob: plain, mediaType: MediaTypeTar},
		{name: "gzip", blob: gz.Bytes(), mediaType: MediaTypeTarGzip},
		{name: "gzip mislabelled as plain", blob: gz.Bytes(), mediaType: MediaTypeTar},
		{name: "plain mislabelled as gzip", blob: plain, mediaType: MediaTypeDockerTarGzip},
		{name: "zstd", blob: []byte{0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x00}, mediaType: MediaTypeTarZstd, wantErr: ErrZstdUnsupported},
		{name: "zstd mislabelled as gzip", blob: []byte{0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x00}, mediaType: MediaTypeTarGzip, wantErr: ErrZstdUnsupported},
		{name: "empty blob labelled zstd", blob: nil, mediaType: MediaTypeTarZstd, wantErr: ErrZstdUnsupported},
		{name: "xz", blob: []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, mediaType: MediaTypeTar, wantErr: ErrUnsupportedCompression},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dest := t.TempDir()
			res, err := ApplyCompressed(context.Background(), dest, bytes.NewReader(tc.blob), tc.mediaType,
				ApplyOptions{NoSameOwner: true})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ApplyCompressed: %v", err)
			}
			if res.DiffID != wantDiffID {
				t.Fatalf("DiffID = %s, want the digest of the uncompressed stream %s", res.DiffID, wantDiffID)
			}
			if got, _ := os.ReadFile(filepath.Join(dest, "f")); string(got) != "hello" {
				t.Fatalf("f = %q", got)
			}
		})
	}
}

func TestApplyEmptyStream(t *testing.T) {
	res, err := Apply(context.Background(), t.TempDir(), bytes.NewReader(nil), ApplyOptions{})
	if err != nil {
		t.Fatalf("Apply on an empty stream: %v", err)
	}
	empty := sha256.Sum256(nil)
	if res.DiffID != "sha256:"+hex.EncodeToString(empty[:]) {
		t.Fatalf("DiffID = %s, want the digest of the empty stream", res.DiffID)
	}
}

func TestApplyMissingDestination(t *testing.T) {
	_, err := Apply(context.Background(), filepath.Join(t.TempDir(), "nope"), bytes.NewReader(nil), ApplyOptions{})
	if err == nil || !strings.Contains(err.Error(), "open destination") {
		t.Fatalf("error = %v, want a clear destination error", err)
	}
}

func TestHaveOpenat2IsStable(t *testing.T) {
	// The probe is cached; calling it twice must not change its mind.
	if haveOpenat2() != haveOpenat2() {
		t.Fatal("openat2 probe is not cached")
	}
	t.Logf("openat2 available: %v", haveOpenat2())
}

func TestResolverRefusesSymlinkComponentsWithoutOpenat2(t *testing.T) {
	// Force the O_NOFOLLOW fallback path and prove it gives the same answer.
	dest := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dest, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)

	for _, useOpenat2 := range []bool{true, false} {
		if useOpenat2 && !haveOpenat2() {
			continue
		}
		r := newResolver(root)
		r.useOpenat2 = useOpenat2
		fd, err := r.open("link/sub", true)
		if err == nil {
			unix.Close(fd)
			t.Fatalf("openat2=%v: resolver followed a symlink", useOpenat2)
		}
		if !errors.Is(err, ErrPathEscape) {
			t.Fatalf("openat2=%v: error = %v, want ErrPathEscape", useOpenat2, err)
		}
		r.Close()
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s should not exist (err %v)", path, err)
	}
}

func assertExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("%s should exist: %v", path, err)
	}
}
