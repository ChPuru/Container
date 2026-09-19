//go:build !windows

package cli

import (
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// notifySignals subscribes ch to the signals hull forwards to a container.
func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, unix.SIGINT, unix.SIGTERM, unix.SIGQUIT, unix.SIGHUP)
}

// signalName renders a signal as the name the engine's kill endpoint takes.
func signalName(sig os.Signal) string {
	switch sig {
	case unix.SIGINT:
		return "SIGINT"
	case unix.SIGTERM:
		return "SIGTERM"
	case unix.SIGQUIT:
		return "SIGQUIT"
	case unix.SIGHUP:
		return "SIGHUP"
	default:
		return ""
	}
}

// interruptSignals are the signals that should unwind a streaming command.
func interruptSignals() []os.Signal {
	return []os.Signal{unix.SIGINT, unix.SIGTERM}
}
