package engine

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

// signalNumbers maps every signal name hull accepts to its Linux number.
//
// The table is written out rather than taken from the syscall package because
// this file must compile for GOOS=windows, where most of those constants do
// not exist, and because the number that matters is the one the container's
// kernel uses, not the daemon's. The values are the x86-64/arm64 Linux ABI,
// which is what every container hull can run uses.
var signalNumbers = map[string]int{
	"HUP": 1, "INT": 2, "QUIT": 3, "ILL": 4, "TRAP": 5, "ABRT": 6, "IOT": 6,
	"BUS": 7, "FPE": 8, "KILL": 9, "USR1": 10, "SEGV": 11, "USR2": 12,
	"PIPE": 13, "ALRM": 14, "TERM": 15, "STKFLT": 16, "CHLD": 17, "CLD": 17,
	"CONT": 18, "STOP": 19, "TSTP": 20, "TTIN": 21, "TTOU": 22, "URG": 23,
	"XCPU": 24, "XFSZ": 25, "VTALRM": 26, "PROF": 27, "WINCH": 28, "IO": 29,
	"POLL": 29, "PWR": 30, "SYS": 31, "UNUSED": 31,
}

// DefaultStopSignal is what a container is stopped with when neither the image
// nor the user named one.
const DefaultStopSignal = "SIGTERM"

// DefaultStopTimeout is how long Stop waits for the stop signal to work before
// it resorts to SIGKILL.
const DefaultStopTimeout = 10

// ParseSignal turns "SIGTERM", "TERM", "term" or "15" into a signal number.
//
// An empty string is an error rather than a default: callers that want a
// default say so themselves, because "no signal" and "the usual signal" are
// different requests and conflating them is how a kill ends up sending the
// wrong thing.
func ParseSignal(s string) (syscall.Signal, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("%w: no signal given", ErrInvalid)
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 || n > 64 {
			return 0, fmt.Errorf("%w: signal %d is outside the 1-64 range", ErrInvalid, n)
		}
		return syscall.Signal(n), nil
	}
	name := strings.ToUpper(s)
	name = strings.TrimPrefix(name, "SIG")
	if n, ok := signalNumbers[name]; ok {
		return syscall.Signal(n), nil
	}
	return 0, fmt.Errorf("%w: %q is not a signal hull knows; use a name such as SIGTERM or a number such as 15",
		ErrInvalid, s)
}

// SignalName renders a signal number as its "SIGTERM" form, falling back to
// the number when it has no name.
func SignalName(sig syscall.Signal) string {
	for name, n := range signalNumbers {
		if n == int(sig) && name != "IOT" && name != "CLD" && name != "POLL" && name != "UNUSED" {
			return "SIG" + name
		}
	}
	return strconv.Itoa(int(sig))
}

// sigKill is SIGKILL's Linux number, spelled portably.
const sigKill = syscall.Signal(9)

// stopSignalFor resolves the signal Stop should send: the container's own
// StopSignal, then the image's, then SIGTERM.
func stopSignalFor(configured string) (syscall.Signal, error) {
	if strings.TrimSpace(configured) == "" {
		configured = DefaultStopSignal
	}
	return ParseSignal(configured)
}
