//go:build windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

// notifySignals subscribes ch to the signals hull forwards to a container.
// Windows delivers Ctrl-C as os.Interrupt and has no SIGQUIT or SIGHUP.
func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}

// signalName renders a signal as the name the engine's kill endpoint takes.
// The container is Linux even when the client is not, so the names are the
// Linux ones.
func signalName(sig os.Signal) string {
	switch sig {
	case os.Interrupt:
		return "SIGINT"
	case syscall.SIGTERM:
		return "SIGTERM"
	default:
		return ""
	}
}

// interruptSignals are the signals that should unwind a streaming command.
func interruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
