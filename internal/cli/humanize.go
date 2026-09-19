package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/volume"
)

// ParseSize converts a human byte size such as "64m", "1.5g" or "1048576"
// into a byte count. Suffixes are binary (1k == 1024), matching Docker.
//
// It delegates to internal/volume so the CLI and the engine cannot disagree
// about what "512m" means.
func ParseSize(s string) (int64, error) {
	n, err := volume.ParseSize(s)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// sizeUnits are the decimal units Docker prints sizes in. Sizes are shown in
// powers of 1000 even though limits are parsed in powers of 1024 — that
// asymmetry is Docker's, and matching it keeps "hull images" output
// comparable with "docker images".
var sizeUnits = []string{"B", "kB", "MB", "GB", "TB", "PB"}

// HumanSize renders a byte count the way Docker does: three significant
// digits and a decimal unit.
func HumanSize(n int64) string {
	if n < 0 {
		return "0B"
	}
	size := float64(n)
	i := 0
	for size >= 1000 && i < len(sizeUnits)-1 {
		size /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%dB", n)
	}
	return fmt.Sprintf("%.3g%s", size, sizeUnits[i])
}

// HumanSizeUnsigned is HumanSize for the unsigned counters the stats endpoint
// reports.
func HumanSizeUnsigned(n uint64) string { return HumanSize(int64(n)) }

// HumanDuration renders a duration as a phrase, the way every Docker listing
// does: "3 minutes", "About an hour", "2 days".
//
// The thresholds are Docker's own, because "ps" output that reads differently
// from "docker ps" is a surprise nobody asked for.
func HumanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	seconds := int(d.Seconds())
	switch {
	case seconds < 1:
		return "Less than a second"
	case seconds == 1:
		return "1 second"
	case seconds < 60:
		return fmt.Sprintf("%d seconds", seconds)
	}
	minutes := int(d.Minutes())
	switch {
	case minutes == 1:
		return "About a minute"
	case minutes < 60:
		return fmt.Sprintf("%d minutes", minutes)
	}
	hours := int(d.Hours() + 0.5)
	switch {
	case hours == 1:
		return "About an hour"
	case hours < 48:
		return fmt.Sprintf("%d hours", hours)
	case hours < 24*7*2:
		return fmt.Sprintf("%d days", hours/24)
	case hours < 24*30*2:
		return fmt.Sprintf("%d weeks", hours/24/7)
	case hours < 24*365*2:
		return fmt.Sprintf("%d months", hours/24/30)
	default:
		return fmt.Sprintf("%d years", int(d.Hours())/24/365)
	}
}

// HumanSince renders how long ago a time was, as "3 minutes ago".
func HumanSince(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return HumanDuration(time.Since(t)) + " ago"
}

// HumanTime parses one of the timestamp spellings the engine emits — RFC3339
// with or without nanoseconds — and renders it as "3 minutes ago". An
// unparseable or zero value comes back as "N/A", never as a Go zero date,
// because a container that has never run must not claim to be 55 years old.
func HumanTime(s string) string {
	t, ok := ParseTime(s)
	if !ok {
		return "N/A"
	}
	return HumanSince(t)
}

// ParseTime decodes an engine timestamp, reporting whether it was both
// parseable and non-zero.
func ParseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05 -0700 MST"} {
		if t, err := time.Parse(layout, s); err == nil {
			if t.IsZero() || t.Unix() <= 0 {
				return time.Time{}, false
			}
			return t, true
		}
	}
	return time.Time{}, false
}

// TruncateID shortens a digest or container id to the 12 characters every
// Docker surface prints, dropping a "sha256:" prefix first.
func TruncateID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Ellipsis shortens s to at most n characters, marking the cut with "…".
// It counts runes, so a multi-byte name is not sliced in half.
func Ellipsis(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string(runes[:n-1]) + "…"
}

// StateSummary renders a container's state the way "docker ps" does when the
// engine has not supplied its own status string.
func StateSummary(state string, started, finished time.Time, exitCode int) string {
	switch state {
	case "running":
		return "Up " + HumanDuration(time.Since(started))
	case "paused":
		return "Up " + HumanDuration(time.Since(started)) + " (Paused)"
	case "restarting":
		return "Restarting (" + fmt.Sprint(exitCode) + ") " + HumanSince(finished)
	case "created":
		return "Created"
	case "exited", "dead":
		if finished.IsZero() {
			return fmt.Sprintf("Exited (%d)", exitCode)
		}
		return fmt.Sprintf("Exited (%d) %s", exitCode, HumanSince(finished))
	default:
		return strings.ToUpper(state[:1]) + state[1:]
	}
}

// JoinNonEmpty joins the non-empty parts with sep, which keeps a missing
// field from leaving a stray separator in a rendered column.
func JoinNonEmpty(sep string, parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}
