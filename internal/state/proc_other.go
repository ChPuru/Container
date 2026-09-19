//go:build !linux

package state

import "time"

// ProcessAlive reports whether pid still names the process hull started at
// startedAt.
//
// Only the Linux implementation can answer this, because it needs field 22 of
// /proc/<pid>/stat to detect a recycled pid. Off Linux (the hull CLI also
// builds for Windows) there is no engine and therefore no container process to
// ask about, so this always reports false. Callers that need a real answer must
// pass their own alive function to Recover.
func ProcessAlive(pid int, startedAt time.Time) bool {
	_ = pid
	_ = startedAt
	return false
}
