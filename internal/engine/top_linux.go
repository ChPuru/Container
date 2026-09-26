//go:build linux

package engine

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ChPuru/hull/internal/events"
	"github.com/ChPuru/hull/internal/types"
)

// procUserHZ is the kernel's clock tick rate for the fields in
// /proc/<pid>/stat. It is 100 on every architecture hull runs on.
const procUserHZ = 100

// Top returns the process table of a running container.
//
// The pids come from the container's cgroup and their details from /proc,
// read from the host. hull deliberately does not run `ps` inside the
// container: a distroless image has no ps at all, and executing an
// attacker-supplied binary to answer a read-only question is exactly the kind
// of thing that turns an information request into a breakout.
//
// psArgs is accepted for Docker compatibility and ignored, because there is no
// ps process to pass it to; the column set is fixed.
func (e *Engine) Top(ctx context.Context, idOrName, psArgs string) (TopResult, error) {
	if err := ctx.Err(); err != nil {
		return TopResult{}, err
	}
	id, err := e.resolveID(idOrName)
	if err != nil {
		return TopResult{}, err
	}
	c, err := e.lookup(id)
	if err != nil {
		return TopResult{}, err
	}
	if c.State != types.StateRunning && c.State != types.StatePaused {
		return TopResult{}, fmt.Errorf("%w: %s is %s", ErrNotRunning, idShort(id), c.State)
	}

	pids, err := e.cgroupProcs(id)
	if err != nil {
		// Without a delegated cgroup there is no process list to read; the
		// container's init is all hull can honestly report.
		if c.Pid > 0 {
			pids = []int{c.Pid}
		} else {
			return TopResult{}, err
		}
	}
	sort.Ints(pids)

	res := TopResult{Titles: []string{"UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"}}
	boot, bootOK := bootTime()
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return TopResult{}, err
		}
		row, ok := procRow(pid, boot, bootOK)
		if !ok {
			continue // it exited between the cgroup read and the /proc read
		}
		res.Processes = append(res.Processes, row)
	}
	e.emit(events.ActionTop, c, nil)
	return res, nil
}

// procRow reads one process's /proc entry into a table row.
func procRow(pid int, boot time.Time, bootOK bool) ([]string, bool) {
	dir := "/proc/" + strconv.Itoa(pid)
	statBytes, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return nil, false
	}
	ppid, utime, stime, starttime, tty, ok := parseProcStat(string(statBytes))
	if !ok {
		return nil, false
	}
	uid := "?"
	if st, serr := os.Stat(dir); serr == nil {
		uid = statOwner(st)
	}
	cmd := readCmdline(dir)
	cpuTime := time.Duration((utime+stime)*1e9/procUserHZ) * time.Nanosecond
	start := "?"
	if bootOK {
		start = boot.Add(time.Duration(starttime) * time.Second / procUserHZ).Format("15:04")
	}
	return []string{
		uid,
		strconv.Itoa(pid),
		strconv.Itoa(ppid),
		"0",
		start,
		ttyName(tty),
		formatCPUTime(cpuTime),
		cmd,
	}, true
}

// parseProcStat pulls the fields Top needs out of a /proc/<pid>/stat line.
//
// The command name in field 2 is wrapped in parentheses and may itself contain
// spaces and parentheses, so the line is split at the LAST ')' rather than by
// whitespace, which is the classic bug in every naive parser of this file.
func parseProcStat(line string) (ppid int, utime, stime, starttime uint64, tty int, ok bool) {
	close := strings.LastIndexByte(line, ')')
	if close < 0 || close+2 > len(line) {
		return 0, 0, 0, 0, 0, false
	}
	fields := strings.Fields(line[close+2:])
	// After the state character, field i of this slice is /proc field i+3.
	if len(fields) < 20 {
		return 0, 0, 0, 0, 0, false
	}
	ppid = atoiSafe(fields[1])        // field 4
	tty = atoiSafe(fields[4])         // field 7
	utime = parseUint(fields[11])     // field 14
	stime = parseUint(fields[12])     // field 15
	starttime = parseUint(fields[19]) // field 22
	return ppid, utime, stime, starttime, tty, true
}

// parseUint reads a non-negative decimal, returning 0 for anything else.
func parseUint(s string) uint64 {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// readCmdline renders a process's argv, falling back to its comm name for a
// kernel thread, which has no command line at all.
func readCmdline(dir string) string {
	if b, err := os.ReadFile(dir + "/cmdline"); err == nil && len(b) > 0 {
		parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		return strings.Join(parts, " ")
	}
	if b, err := os.ReadFile(dir + "/comm"); err == nil {
		return "[" + strings.TrimSpace(string(b)) + "]"
	}
	return "?"
}

// ttyName renders a tty device number the way ps does.
func ttyName(dev int) string {
	if dev == 0 {
		return "?"
	}
	major := (dev >> 8) & 0xfff
	minor := dev & 0xff
	if major == 136 {
		return "pts/" + strconv.Itoa(minor)
	}
	return "?"
}

// formatCPUTime renders accumulated CPU time as ps does, MM:SS or HH:MM:SS.
func formatCPUTime(d time.Duration) string {
	total := int(d.Seconds())
	h, rem := total/3600, total%3600
	m, s := rem/60, rem%60
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("00:%02d:%02d", m, s)
}
