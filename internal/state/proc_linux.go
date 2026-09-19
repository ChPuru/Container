//go:build linux

package state

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// userHZ is the kernel's clock-tick rate as exposed through /proc/<pid>/stat.
// It is 100 on every architecture Linux supports for USER_HZ, and WSL's kernel
// is no exception; Go has no portable sysconf(_SC_CLK_TCK).
const userHZ = 100

// startTimeSlack is how far /proc's idea of when a process started may drift
// from the timestamp hull recorded in Container.StartedAt before we conclude
// that the pid was recycled by an unrelated process. The two clocks are the
// same clock, so the only drift is the gap between fork and the daemon writing
// the record.
const startTimeSlack = 10 * time.Second

var (
	bootTimeOnce sync.Once
	bootTimeVal  time.Time
	bootTimeErr  error
)

// bootTime returns the wall-clock instant the kernel booted, read from
// /proc/stat's btime line. Adding a process's starttime (in clock ticks) to it
// yields the wall-clock instant that process started.
func bootTime() (time.Time, error) {
	bootTimeOnce.Do(func() {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			bootTimeErr = err
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			rest, ok := strings.CutPrefix(line, "btime ")
			if !ok {
				continue
			}
			secs, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				bootTimeErr = err
				return
			}
			bootTimeVal = time.Unix(secs, 0)
			return
		}
		bootTimeErr = errors.New("no btime line in /proc/stat")
	})
	return bootTimeVal, bootTimeErr
}

// procStartTime returns the wall-clock start time of pid, parsed from field 22
// of /proc/<pid>/stat, and whether the process is a zombie.
//
// Field 2 (comm) is the executable name in parentheses and may itself contain
// spaces and parentheses, so the fields after it are found from the *last*
// closing parenthesis, never by splitting the whole line.
func procStartTime(pid int) (start time.Time, zombie bool, err error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return time.Time{}, false, err
	}
	line := string(data)
	closeParen := strings.LastIndexByte(line, ')')
	if closeParen < 0 || closeParen+2 > len(line) {
		return time.Time{}, false, errors.New("malformed /proc/<pid>/stat: no comm field")
	}
	// Fields after the closing paren are stat fields 3..52.
	fields := strings.Fields(line[closeParen+1:])
	const startTimeField = 22
	idx := startTimeField - 3
	if len(fields) <= idx {
		return time.Time{}, false, errors.New("malformed /proc/<pid>/stat: too few fields")
	}
	zombie = fields[0] == "Z"
	ticks, err := strconv.ParseUint(fields[idx], 10, 64)
	if err != nil {
		return time.Time{}, zombie, err
	}
	boot, err := bootTime()
	if err != nil {
		return time.Time{}, zombie, err
	}
	nsec := (int64(ticks) % userHZ) * (int64(time.Second) / userHZ)
	return boot.Add(time.Duration(int64(ticks)/userHZ) * time.Second).Add(time.Duration(nsec)), zombie, nil
}

// ProcessAlive reports whether pid still names the very process hull started at
// startedAt.
//
// A bare kill(pid, 0) is not enough: after a daemon restart the pid may have
// been recycled by something completely unrelated, and reporting that container
// as running would be worse than reporting it exited. ProcessAlive therefore
// also compares field 22 of /proc/<pid>/stat (the process start time, in clock
// ticks since boot) against startedAt, and calls a mismatch dead. A zombie is
// reported dead as well: its exit status has not been reaped, but it is not
// running anything.
//
// A zero startedAt means the caller has no recorded start time, in which case
// mere existence of the pid is accepted.
func ProcessAlive(pid int, startedAt time.Time) bool {
	if pid <= 0 {
		return false
	}
	start, zombie, err := procStartTime(pid)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false // no such process
		}
		// /proc is unreadable for a reason we do not understand. Err on the
		// side of not reaping a container that may still be running.
		return true
	}
	if zombie {
		return false
	}
	if startedAt.IsZero() {
		return true
	}
	delta := start.Sub(startedAt)
	if delta < 0 {
		delta = -delta
	}
	return delta <= startTimeSlack
}
