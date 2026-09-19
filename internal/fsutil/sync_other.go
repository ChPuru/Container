//go:build !linux

package fsutil

// fsyncDir is a documented no-op off Linux: Windows offers no way to flush a
// directory entry and does not need one, because NTFS metadata is journalled.
// Returning nil keeps WriteFileAtomic and CopyFile usable in the Windows CLI
// build instead of failing every config write.
func fsyncDir(string) error { return nil }
