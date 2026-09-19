package wslbridge

import (
	"io"
	"os"
)

// stderrWriter is the destination for the hidden subcommands' -verbose logging.
// It is a function rather than a direct os.Stderr reference so a test can assert
// that nothing the bridge logs ever reaches standard output, which on the relay
// side carries the frame stream.
var stderrWriter = func() io.Writer { return os.Stderr }
