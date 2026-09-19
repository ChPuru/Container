package cli

import (
	"errors"
	"testing"
)

// TestStartFailureExitCodes checks the mapping a script depends on when a
// container will not start: 127 for a command the image does not have, 126 for
// one it has but cannot run, and hull's own 125 for everything else.
//
// The messages are the real ones, as they arrive after the shim, the engine
// and the API have each wrapped them.
func TestStartFailureExitCodes(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want int
	}{
		{
			name: "crun cannot find the executable",
			msg:  `starting container process caused: exec: "nope": executable file not found in $PATH`,
			want: ExitNotFound,
		},
		{
			name: "runc phrasing",
			msg:  `OCI runtime create failed: unable to start container process: exec: "sh": executable file not found in $PATH: unknown`,
			want: ExitNotFound,
		},
		{
			name: "the entrypoint binary is missing",
			msg:  `hull-init: exec /app/server: no such file or directory`,
			want: ExitNotFound,
		},
		{
			name: "the binary is not executable",
			msg:  `starting container process caused: exec /app/run.sh: permission denied`,
			want: ExitCannotInvoke,
		},
		{
			name: "the binary is for another architecture",
			msg:  `hull-init: exec /app/server: exec format error`,
			want: ExitCannotInvoke,
		},
		{
			name: "the entrypoint names a directory",
			msg:  `OCI runtime exec failed: exec /app: is a directory`,
			want: ExitCannotInvoke,
		},
		{
			name: "an unrelated engine failure stays hull's own",
			msg:  `cannot create bundle: no space left on device`,
			want: ExitFailure,
		},
		{
			name: "a missing config file is not a missing command",
			msg:  `open /var/lib/hull/config.json: no such file or directory`,
			want: ExitFailure,
		},
		{
			name: "a refused connection stays hull's own",
			msg:  `dial unix /var/lib/hull/run/hull.sock: connect: connection refused`,
			want: ExitFailure,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := StartFailure(errors.New(tc.msg))
			if got := ExitCodeOf(err); got != tc.want {
				t.Errorf("StartFailure(%q) exited %d, want %d", tc.msg, got, tc.want)
			}
			// The original message must survive, or the user is told the
			// exit status and nothing about why.
			if err == nil || err.Error() != tc.msg {
				t.Errorf("StartFailure lost the message: %v", err)
			}
		})
	}

	if err := StartFailure(nil); err != nil {
		t.Errorf("StartFailure(nil) = %v, want nil", err)
	}
}
