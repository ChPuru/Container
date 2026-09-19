package cli

import "strings"

// StartFailure classifies a runtime's refusal to start a container or an exec
// and returns an error carrying the exit status a shell expects.
//
// The convention is the shell's and Docker copies it: 127 means the command
// was not found, 126 means it was found but could not be run, and anything
// else stays hull's own 125. Scripts branch on these — "command not found" is
// a typo in the image's CMD, while 125 is hull or the engine failing — so
// collapsing them all into 125 loses the distinction that matters most at the
// moment a container will not start.
//
// A nil error passes through, and an error that matches nothing keeps the
// default status: guessing 127 for an unrelated failure would be worse than
// admitting the failure was hull's.
func StartFailure(err error) error {
	if err == nil {
		return nil
	}
	switch code := classifyStartFailure(err.Error()); code {
	case ExitNotFound, ExitCannotInvoke:
		return &ExitError{Code: code, Err: err}
	default:
		return err
	}
}

// classifyStartFailure reads a runtime's complaint and decides which exit
// status it corresponds to.
//
// The runtimes do not agree on the wording — crun, runc and hull's own native
// driver each phrase it differently, and the message arrives having been
// wrapped by the shim, the engine and the API on the way — so the match is on
// the fragment they share rather than on a whole sentence.
func classifyStartFailure(msg string) int {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "executable file not found"),
		strings.Contains(m, "no such file or directory") && mentionsExec(m),
		strings.Contains(m, "not found in $path"):
		return ExitNotFound
	case strings.Contains(m, "permission denied") && mentionsExec(m),
		strings.Contains(m, "exec format error"),
		strings.Contains(m, "is a directory") && mentionsExec(m),
		strings.Contains(m, "not a directory") && mentionsExec(m):
		return ExitCannotInvoke
	default:
		return ExitFailure
	}
}

// mentionsExec reports whether a message is about running the container's own
// process, as opposed to some unrelated file the engine could not open.
//
// Without this guard a failure to read a config file would be reported as the
// container's command being missing, which sends the user looking in exactly
// the wrong place.
func mentionsExec(m string) bool {
	for _, marker := range []string{
		"exec", "starting container process", "create process",
		"runtime", "entrypoint", "cmd",
	} {
		if strings.Contains(m, marker) {
			return true
		}
	}
	return false
}
