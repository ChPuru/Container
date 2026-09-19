package tui

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

// ellipsis is the single rune used to mark truncated text. One rune rather
// than three dots keeps a column an exact width.
const ellipsis = '…'

// Truncate shortens s to at most w cells, marking the cut with an ellipsis.
// It counts runes, not bytes, so a multi-byte name occupies the width it
// actually occupies. Zero-width and double-width runes are out of scope: hull
// renders container names, image references and log text, none of which are
// laid out on a CJK grid.
func Truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w == 1 {
		return string(ellipsis)
	}
	return string(r[:w-1]) + string(ellipsis)
}

// Pad returns s padded with spaces to exactly w cells, truncating when it is
// too long. align selects which side the padding goes on.
func Pad(s string, w int, align Align) string {
	if w <= 0 {
		return ""
	}
	s = Truncate(s, w)
	gap := w - len([]rune(s))
	if gap <= 0 {
		return s
	}
	switch align {
	case AlignRight:
		return strings.Repeat(" ", gap) + s
	case AlignCenter:
		left := gap / 2
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", gap-left)
	default:
		return s + strings.Repeat(" ", gap)
	}
}

// Align selects how a cell's text sits in its column.
type Align int

// The three alignments the table widget supports.
const (
	// AlignLeft is the default and is right for names and identifiers.
	AlignLeft Align = iota
	// AlignRight is right for numbers, so the digits line up.
	AlignRight
	// AlignCenter is used by headings in the overlay.
	AlignCenter
)

// HumanBytes formats a byte count the way a person reads it: three
// significant figures and a binary unit. It is used for memory and for free
// disk space, both of which are meaningless as raw integers on a status bar.
func HumanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatUint(n, 10) + "B"
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 5; v /= unit {
		div *= unit
		exp++
	}
	val := float64(n) / float64(div)
	suffix := [...]string{"K", "M", "G", "T", "P", "E"}[exp]
	switch {
	case val < 10:
		return strconv.FormatFloat(val, 'f', 2, 64) + suffix
	case val < 100:
		return strconv.FormatFloat(val, 'f', 1, 64) + suffix
	default:
		return strconv.FormatFloat(val, 'f', 0, 64) + suffix
	}
}

// HumanDuration formats an age or an uptime in the compact form the container
// world uses: "3s", "4m12s", "2h05m", "6d3h", "3w".
func HumanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return "0s"
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		return fmt.Sprintf("%dm%02ds", m, s)
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		return fmt.Sprintf("%dh%02dm", h, m)
	case d < 14*24*time.Hour:
		days := int(d.Hours()) / 24
		h := int(d.Hours()) - days*24
		return fmt.Sprintf("%dd%dh", days, h)
	default:
		return strconv.Itoa(int(d.Hours())/(24*7)) + "w"
	}
}

// HumanPercent formats a percentage for a fixed-width column, keeping one
// decimal below 100 and dropping it above.
func HumanPercent(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return "-"
	}
	if v >= 100 {
		return strconv.FormatFloat(v, 'f', 0, 64) + "%"
	}
	return strconv.FormatFloat(v, 'f', 1, 64) + "%"
}

// CPUPercent computes a container's CPU usage from one stats sample, using
// Docker's formula: the container's CPU-time delta over the system's CPU-time
// delta, scaled by the number of online CPUs.
//
// It returns 0 rather than an absurd number whenever the sample has no
// previous reading to difference against, which is the case for the very first
// sample of a stream and for every sample on a host where hull cannot read
// cgroup CPU accounting at all.
func CPUPercent(s types.Stats) float64 {
	if s.CPUUsage <= s.PreCPUUsage || s.SystemUsage <= s.PreSystemUsage {
		return 0
	}
	cpuDelta := float64(s.CPUUsage - s.PreCPUUsage)
	sysDelta := float64(s.SystemUsage - s.PreSystemUsage)
	if sysDelta <= 0 {
		return 0
	}
	cpus := s.OnlineCPUs
	if cpus <= 0 {
		cpus = 1
	}
	return cpuDelta / sysDelta * float64(cpus) * 100
}

// MemoryUsage returns the memory a container is using, with the page cache
// subtracted. Cache is reclaimable, and counting it is how every naive stats
// display ends up claiming a sleeping container is using two gigabytes.
func MemoryUsage(s types.Stats) uint64 {
	if s.MemoryCache >= s.MemoryUsage {
		return 0
	}
	return s.MemoryUsage - s.MemoryCache
}

// MemoryPercent returns memory usage as a percentage of the container's limit,
// or 0 when there is no limit to measure against - which, on a host with no
// delegated cgroup v2 controllers, is every container.
func MemoryPercent(s types.Stats) float64 {
	if s.MemoryLimit == 0 {
		return 0
	}
	return float64(MemoryUsage(s)) / float64(s.MemoryLimit) * 100
}

// ShortID trims a 64-hex container or image id to the twelve characters every
// container tool shows, leaving anything shorter alone.
func ShortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Uptime returns how long a container has been in its current state, measured
// from now.
func Uptime(c types.Container, now time.Time) time.Duration {
	switch c.State {
	case types.StateRunning, types.StatePaused, types.StateRestarting:
		if c.StartedAt.IsZero() {
			return 0
		}
		return now.Sub(c.StartedAt)
	case types.StateExited, types.StateDead:
		if c.FinishedAt.IsZero() {
			return 0
		}
		return now.Sub(c.FinishedAt)
	default:
		if c.Created.IsZero() {
			return 0
		}
		return now.Sub(c.Created)
	}
}

// StateSummary renders a container's state the way the ps column wants it: the
// state itself, plus the exit code for something that died and the health
// status for something being probed.
func StateSummary(c types.Container) string {
	switch c.State {
	case types.StateRunning:
		if c.Health != nil && c.Health.Status != "" {
			return "running (" + c.Health.Status + ")"
		}
		return "running"
	case types.StateExited, types.StateDead:
		return string(c.State) + " (" + strconv.Itoa(c.ExitCode) + ")"
	default:
		return string(c.State)
	}
}

// sortPortKeys orders "80/tcp" style keys by port number and then by
// protocol. Sorting them as strings would put 443 before 80, which is how
// every hand-rolled port list ends up looking wrong.
func sortPortKeys(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		pi, si := splitPortKey(keys[i])
		pj, sj := splitPortKey(keys[j])
		if pi != pj {
			return pi < pj
		}
		return si < sj
	})
}

// splitPortKey splits "80/tcp" into 80 and "tcp". A key that is not in that
// shape sorts last, by its own text.
func splitPortKey(k string) (int, string) {
	num, proto, ok := strings.Cut(k, "/")
	if !ok {
		proto = ""
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 1 << 30, k
	}
	return n, proto
}

// PortStrings renders a container's published ports as "0.0.0.0:8080->80/tcp"
// lines, sorted so the list does not dance between frames. Unpublished exposed
// ports appear bare, as "80/tcp".
func PortStrings(c types.Container) []string {
	ports := c.NetworkSettings.Ports
	out := make([]string, 0, len(ports))
	keys := make([]string, 0, len(ports))
	for k := range ports {
		keys = append(keys, k)
	}
	sortPortKeys(keys)
	for _, k := range keys {
		bindings := ports[k]
		if len(bindings) == 0 {
			out = append(out, k)
			continue
		}
		for _, b := range bindings {
			host := b.HostIP
			if host == "" {
				host = "0.0.0.0"
			}
			out = append(out, host+":"+b.HostPort+"->"+k)
		}
	}
	if len(out) == 0 {
		exposed := make([]string, 0, len(c.Config.ExposedPorts))
		for k := range c.Config.ExposedPorts {
			exposed = append(exposed, k)
		}
		sortPortKeys(exposed)
		out = exposed
	}
	return out
}

// warningsLabel is where hull's API layer records a container's
// unenforceable-limit warnings. The create response carries them directly, but
// a container created by compose is looked at long after that response was
// discarded, so the engine also writes them onto the container as this label.
// The constant is duplicated here rather than imported: internal/api sits
// beside this package, not beneath it.
const warningsLabel = "com.hull.warnings"

// ContainerWarnings returns the warnings the engine produced while building a
// container's bundle, read from the container's own record.
//
// This is smaller than it is important. bundle.Generate returns warnings
// instead of failing when a resource limit cannot be enforced on this host's
// hybrid cgroups, so a container created with --memory 512m may be running
// with no memory limit at all. A dashboard that does not surface them lets the
// user silently get unlimited containers, which is exactly the failure the
// warnings exist to prevent.
func ContainerWarnings(c types.Container) []string {
	raw := c.Config.Labels[warningsLabel]
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ImageName picks the most human of the names an image has: the reference the
// user asked for, then the image id, shortened.
func ImageName(c types.Container) string {
	if c.ImageRef != "" {
		return c.ImageRef
	}
	return ShortID(c.Image)
}

// EventLine renders one engine event as a single line: time, type, action and
// whatever names the actor.
func EventLine(e types.Event, local *time.Location) string {
	ts := time.Unix(e.Time, 0)
	if e.TimeNano != 0 {
		ts = time.Unix(0, e.TimeNano)
	}
	if local != nil {
		ts = ts.In(local)
	}
	name := e.Actor.Attributes["name"]
	if name == "" {
		name = ShortID(e.Actor.ID)
	}
	var b strings.Builder
	b.WriteString(ts.Format("15:04:05"))
	b.WriteByte(' ')
	b.WriteString(e.Type)
	b.WriteByte(' ')
	b.WriteString(e.Action)
	if name != "" {
		b.WriteByte(' ')
		b.WriteString(name)
	}
	return b.String()
}

// wrapLines hard-wraps s to width w, returning at least one line. It is used
// for warning text and help paragraphs, where losing the tail of a sentence to
// truncation would hide the remedy.
func wrapLines(s string, w int) []string {
	if w <= 0 {
		return []string{""}
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var (
		out  []string
		line strings.Builder
	)
	for _, word := range words {
		switch {
		case line.Len() == 0:
			line.WriteString(word)
		case line.Len()+1+len([]rune(word)) <= w:
			line.WriteByte(' ')
			line.WriteString(word)
		default:
			out = append(out, line.String())
			line.Reset()
			line.WriteString(word)
		}
		for len([]rune(line.String())) > w {
			r := []rune(line.String())
			out = append(out, string(r[:w]))
			rest := string(r[w:])
			line.Reset()
			line.WriteString(rest)
		}
	}
	if line.Len() > 0 {
		out = append(out, line.String())
	}
	return out
}
