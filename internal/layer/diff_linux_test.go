//go:build linux

package layer

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// readTar indexes a tar blob by entry name.
func readTar(t *testing.T, blob []byte) map[string]*tar.Header {
	t.Helper()
	out := make(map[string]*tar.Header)
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read diff tar: %v", err)
		}
		h := *hdr
		out[hdr.Name] = &h
		if _, err := io.Copy(io.Discard, tr); err != nil {
			t.Fatalf("drain %q: %v", hdr.Name, err)
		}
	}
	return out
}

func names(m map[string]*tar.Header) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestDiffRoundTrip(t *testing.T) {
	src := t.TempDir()
	mustMkdirAll(t, filepath.Join(src, "usr/bin"))
	mustMkdirAll(t, filepath.Join(src, "empty"))
	mustWrite(t, filepath.Join(src, "usr/bin/tool"), "#!/bin/sh\n")
	mustWrite(t, filepath.Join(src, "usr/bin/suid"), "setuid\n")
	if err := os.Chmod(filepath.Join(src, "usr/bin/suid"), 0o4755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("tool", filepath.Join(src, "usr/bin/link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(src, "usr/bin/tool"), filepath.Join(src, "usr/bin/hard")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mknod(filepath.Join(src, "fifo"), unix.S_IFIFO|0o644, 0); err != nil {
		t.Fatalf("mknod fifo: %v", err)
	}
	stamp := time.Unix(1500000000, 0)
	for _, p := range []string{"usr", "usr/bin", "empty", "usr/bin/tool"} {
		if err := os.Chtimes(filepath.Join(src, p), stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	res, err := Diff(context.Background(), src, "", &buf)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if res.Whiteouts != 0 {
		t.Fatalf("Whiteouts = %d, want 0", res.Whiteouts)
	}
	if res.Size != int64(buf.Len()) {
		t.Fatalf("Size = %d, want %d", res.Size, buf.Len())
	}
	sum := sha256.Sum256(buf.Bytes())
	if want := "sha256:" + hex.EncodeToString(sum[:]); res.DiffID != want {
		t.Fatalf("DiffID = %s, want %s", res.DiffID, want)
	}

	hdrs := readTar(t, buf.Bytes())
	for _, want := range []string{"empty/", "fifo", "usr/", "usr/bin/", "usr/bin/hard", "usr/bin/link", "usr/bin/suid", "usr/bin/tool"} {
		if _, ok := hdrs[want]; !ok {
			t.Fatalf("diff is missing %q; got %v", want, names(hdrs))
		}
	}
	// Whichever of the two names comes first in sorted order carries the
	// content; the other becomes a hardlink to it.
	if h := hdrs["usr/bin/hard"]; h.Typeflag != tar.TypeReg {
		t.Fatalf("usr/bin/hard = %c, want a regular file", h.Typeflag)
	}
	if h := hdrs["usr/bin/tool"]; h.Typeflag != tar.TypeLink || h.Linkname != "usr/bin/hard" {
		t.Fatalf("usr/bin/tool = %c %q, want a hardlink to usr/bin/hard", h.Typeflag, h.Linkname)
	}
	if h := hdrs["usr/bin/link"]; h.Typeflag != tar.TypeSymlink || h.Linkname != "tool" {
		t.Fatalf("symlink entry = %c %q", h.Typeflag, h.Linkname)
	}

	dst := t.TempDir()
	if _, err := Apply(context.Background(), dst, bytes.NewReader(buf.Bytes()),
		ApplyOptions{NoSameOwner: true}); err != nil {
		t.Fatalf("Apply the diff back: %v", err)
	}
	compareTrees(t, src, dst)
}

// compareTrees fails unless two directory trees are indistinguishable in the
// dimensions a layer is supposed to preserve.
func compareTrees(t *testing.T, a, b string) {
	t.Helper()
	walk := func(root string) map[string]string {
		got := make(map[string]string)
		if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			if rel == "." {
				return nil
			}
			var st unix.Stat_t
			if err := unix.Lstat(p, &st); err != nil {
				return err
			}
			desc := ""
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFLNK:
				target, err := os.Readlink(p)
				if err != nil {
					return err
				}
				desc = "symlink->" + target
			case unix.S_IFREG:
				content, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				desc = "reg:" + string(content)
			case unix.S_IFDIR:
				desc = "dir"
			case unix.S_IFIFO:
				desc = "fifo"
			default:
				desc = "other"
			}
			got[rel] = desc + " mode=" + fmtOct(st.Mode&0o7777) +
				" mtime=" + fmtInt(st.Mtim.Sec) + " nlink=" + fmtInt(int64(st.Nlink))
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
		return got
	}
	ga, gb := walk(a), walk(b)
	if len(ga) != len(gb) {
		t.Fatalf("tree sizes differ: %d vs %d\n%v\n%v", len(ga), len(gb), ga, gb)
	}
	for k, va := range ga {
		vb, ok := gb[k]
		if !ok {
			t.Fatalf("%s missing from the applied tree", k)
		}
		if va != vb {
			t.Fatalf("%s: %q vs %q", k, va, vb)
		}
	}
}

func fmtOct(v uint32) string {
	const digits = "01234567"
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{digits[v&7]}, b...)
		v >>= 3
	}
	return string(b)
}

func fmtInt(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestDiffOverlayWhiteout(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	upper := t.TempDir()
	mustMkdirAll(t, filepath.Join(upper, "d"))
	if err := unix.Mknod(filepath.Join(upper, "d/deleted"), unix.S_IFCHR|0o000, 0); err != nil {
		t.Skipf("cannot create an overlay whiteout here: %v", err)
	}
	mustWrite(t, filepath.Join(upper, "d/added"), "new")

	var buf bytes.Buffer
	res, err := Diff(context.Background(), upper, "", &buf)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if res.Whiteouts != 1 {
		t.Fatalf("Whiteouts = %d, want 1", res.Whiteouts)
	}
	hdrs := readTar(t, buf.Bytes())
	wh := "d/" + WhiteoutPrefix + "deleted"
	if h, ok := hdrs[wh]; !ok {
		t.Fatalf("missing %q; got %v", wh, names(hdrs))
	} else if h.Typeflag != tar.TypeReg || h.Size != 0 {
		t.Fatalf("whiteout entry = %c size %d, want an empty regular file", h.Typeflag, h.Size)
	}
	if _, ok := hdrs["d/deleted"]; ok {
		t.Fatal("the character device itself leaked into the layer")
	}

	// And it round-trips: applying the diff deletes the file.
	dst := t.TempDir()
	mustMkdirAll(t, filepath.Join(dst, "d"))
	mustWrite(t, filepath.Join(dst, "d/deleted"), "old")
	if _, err := Apply(context.Background(), dst, bytes.NewReader(buf.Bytes()), ApplyOptions{}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	assertMissing(t, filepath.Join(dst, "d/deleted"))
	assertExists(t, filepath.Join(dst, "d/added"))
}

func TestDiffOpaqueDirectory(t *testing.T) {
	upper := t.TempDir()
	dir := filepath.Join(upper, "opq")
	mustMkdirAll(t, dir)
	mustWrite(t, filepath.Join(dir, "kept"), "new")
	if err := unix.Setxattr(dir, OpaqueXattrUser, []byte("y"), 0); err != nil {
		t.Skipf("cannot set %s here: %v", OpaqueXattrUser, err)
	}

	var buf bytes.Buffer
	res, err := Diff(context.Background(), upper, "", &buf)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if res.Whiteouts != 1 {
		t.Fatalf("Whiteouts = %d, want 1", res.Whiteouts)
	}
	hdrs := readTar(t, buf.Bytes())
	opq := "opq/" + WhiteoutOpaqueDir
	if _, ok := hdrs[opq]; !ok {
		t.Fatalf("missing %q; got %v", opq, names(hdrs))
	}
	// The overlay bookkeeping xattr must not be copied into the layer.
	if h := hdrs["opq/"]; h.PAXRecords[xattrPAXPrefix+OpaqueXattrUser] != "" {
		t.Fatalf("overlay xattr leaked into the layer: %v", h.PAXRecords)
	}

	// Applying it onto a populated directory empties that directory.
	dst := t.TempDir()
	mustMkdirAll(t, filepath.Join(dst, "opq/old"))
	mustWrite(t, filepath.Join(dst, "opq/old/stale"), "old")
	if _, err := Apply(context.Background(), dst, bytes.NewReader(buf.Bytes()),
		ApplyOptions{NoSameOwner: true}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	assertMissing(t, filepath.Join(dst, "opq/old"))
	assertExists(t, filepath.Join(dst, "opq/kept"))
}

func TestDiffAgainstLower(t *testing.T) {
	lower, upper := t.TempDir(), t.TempDir()
	stamp := time.Unix(1400000000, 0)

	// Unchanged subtree: identical in both, so nothing about it may be emitted.
	for _, root := range []string{lower, upper} {
		mustMkdirAll(t, filepath.Join(root, "same"))
		mustWrite(t, filepath.Join(root, "same/x"), "same")
		if err := os.Chtimes(filepath.Join(root, "same/x"), stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(filepath.Join(root, "same"), stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	// Changed, added and removed entries.
	mustMkdirAll(t, filepath.Join(lower, "a"))
	mustWrite(t, filepath.Join(lower, "a/gone"), "old")
	mustWrite(t, filepath.Join(lower, "a/changed"), "old")
	mustWrite(t, filepath.Join(lower, "removed-at-root"), "old")
	mustMkdirAll(t, filepath.Join(upper, "a"))
	mustWrite(t, filepath.Join(upper, "a/changed"), "brand new content")
	mustWrite(t, filepath.Join(upper, "a/added"), "new")

	var buf bytes.Buffer
	res, err := Diff(context.Background(), upper, lower, &buf)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if res.Whiteouts != 2 {
		t.Fatalf("Whiteouts = %d, want 2", res.Whiteouts)
	}
	hdrs := readTar(t, buf.Bytes())
	for _, want := range []string{
		"a/", "a/added", "a/changed",
		WhiteoutPrefix + "removed-at-root",
		"a/" + WhiteoutPrefix + "gone",
	} {
		if _, ok := hdrs[want]; !ok {
			t.Fatalf("diff is missing %q; got %v", want, names(hdrs))
		}
	}
	for _, unwanted := range []string{"same/", "same/x"} {
		if _, ok := hdrs[unwanted]; ok {
			t.Fatalf("unchanged entry %q leaked into the diff: %v", unwanted, names(hdrs))
		}
	}
}

func TestDiffContextCancellation(t *testing.T) {
	src := t.TempDir()
	mustWrite(t, filepath.Join(src, "f"), "x")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Diff(ctx, src, "", io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestDiffMissingUpper(t *testing.T) {
	_, err := Diff(context.Background(), filepath.Join(t.TempDir(), "nope"), "", io.Discard)
	if err == nil {
		t.Fatal("want an error for a missing upperdir")
	}
}

func TestDiffXattrsRoundTrip(t *testing.T) {
	src := t.TempDir()
	f := filepath.Join(src, "f")
	mustWrite(t, f, "x")
	if err := unix.Setxattr(f, "user.hull", []byte("v1"), 0); err != nil {
		t.Skipf("filesystem does not support user xattrs: %v", err)
	}
	var buf bytes.Buffer
	if _, err := Diff(context.Background(), src, "", &buf); err != nil {
		t.Fatalf("Diff: %v", err)
	}
	hdrs := readTar(t, buf.Bytes())
	if got := hdrs["f"].PAXRecords[xattrPAXPrefix+"user.hull"]; got != "v1" {
		t.Fatalf("xattr record = %q, want %q", got, "v1")
	}
	dst := t.TempDir()
	if _, err := Apply(context.Background(), dst, bytes.NewReader(buf.Bytes()),
		ApplyOptions{NoSameOwner: true}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	val := make([]byte, 16)
	n, err := unix.Lgetxattr(filepath.Join(dst, "f"), "user.hull", val)
	if err != nil {
		t.Fatalf("xattr did not survive the round trip: %v", err)
	}
	if string(val[:n]) != "v1" {
		t.Fatalf("xattr = %q, want %q", val[:n], "v1")
	}
}
