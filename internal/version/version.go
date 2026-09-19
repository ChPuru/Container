// Package version carries build identity for every hull binary.
package version

// These are overridden at link time via -X.
var (
	Version   = "0.1.0-dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// APIVersion is the Docker Engine API version hull claims on /_ping and /version.
// 1.43 is the last version before the build endpoints were reshuffled, and is what
// the docker CLI, compose and Testcontainers all negotiate down to happily.
const APIVersion = "1.43"

// MinAPIVersion is the oldest Docker Engine API version hull will serve.
const MinAPIVersion = "1.24"

// DockerVersion is what hull reports as the Docker daemon version for clients
// that gate features on it. It is deliberately a real, recent version.
const DockerVersion = "28.4.0"
