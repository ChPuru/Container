//go:build !linux

package runtime

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/ChPuru/hull/internal/oci/runtimespec"
)

// NativeName is the value HostConfig.Runtime takes to select hull's own
// runtime rather than an external OCI binary.
const NativeName = "hull"

// InitBinaryEnv names the environment variable that overrides where hull looks
// for the hull-init binary.
const InitBinaryEnv = "HULL_INIT"

// NativeRuntime is hull's own container runtime. Off Linux it exists only so
// the Windows CLI can name it, compare it against HostConfig.Runtime and print
// its features; every method reports ErrUnsupported.
type NativeRuntime struct {
	root string
}

var _ Runtime = (*NativeRuntime)(nil)

// unsupported builds the one error every method on this stub returns.
func unsupported(op string) error {
	return fmt.Errorf("runtime: cannot %s a container on %s; hull's containers run inside the "+
		"Linux engine distro, and the %s CLI talks to the daemon rather than running them itself: %w",
		op, runtime.GOOS, runtime.GOOS, ErrUnsupported)
}

// NewNative returns a stub runtime. It never fails, so the CLI can construct
// one to answer "what would this runtime be called".
func NewNative(root string, features Features) (*NativeRuntime, error) {
	return &NativeRuntime{root: root}, nil
}

// Name returns "hull".
func (r *NativeRuntime) Name() string { return NativeName }

// Root returns the state root the stub was constructed with.
func (r *NativeRuntime) Root() string { return r.root }

// SetInitBinary is accepted and ignored off Linux.
func (r *NativeRuntime) SetInitBinary(b []byte) error { return unsupported("configure") }

// InitBinaryPath reports that there is no init binary off Linux.
func (r *NativeRuntime) InitBinaryPath() string { return "" }

// Create is not supported off Linux.
func (r *NativeRuntime) Create(ctx context.Context, id, bundleDir string, opts CreateOptions) (*Status, error) {
	return nil, unsupported("create")
}

// Start is not supported off Linux.
func (r *NativeRuntime) Start(ctx context.Context, id string) error { return unsupported("start") }

// State is not supported off Linux.
func (r *NativeRuntime) State(ctx context.Context, id string) (*Status, error) {
	return nil, unsupported("inspect")
}

// Kill is not supported off Linux.
func (r *NativeRuntime) Kill(ctx context.Context, id string, sig syscall.Signal, all bool) error {
	return unsupported("signal")
}

// Delete is not supported off Linux.
func (r *NativeRuntime) Delete(ctx context.Context, id string, force bool) error {
	return unsupported("delete")
}

// Exec is not supported off Linux.
func (r *NativeRuntime) Exec(ctx context.Context, id string, process *runtimespec.Process, opts ExecOptions) (*Status, error) {
	return nil, unsupported("exec into")
}

// Pause is not supported off Linux.
func (r *NativeRuntime) Pause(ctx context.Context, id string) error { return unsupported("pause") }

// Resume is not supported off Linux.
func (r *NativeRuntime) Resume(ctx context.Context, id string) error { return unsupported("resume") }

// Console is not supported off Linux.
func (r *NativeRuntime) Console(id string) (*os.File, error) { return nil, unsupported("attach to") }

// Features reports the driver name and the host probe's explanation of why it
// found nothing.
func (r *NativeRuntime) Features(ctx context.Context) (RuntimeFeatures, error) {
	probe, err := ProbeFeatures(ctx)
	if err != nil {
		return RuntimeFeatures{}, err
	}
	return RuntimeFeatures{
		Name:        NativeName,
		Version:     "hull-native",
		OCIVersions: []string{runtimespec.Version},
		Kernel:      probe.Kernel,
		Probe:       probe,
		Warnings:    probe.Warnings,
	}, nil
}
