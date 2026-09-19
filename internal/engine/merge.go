package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/bundle"
	"github.com/rahuldhali/hull/internal/types"
)

// HealthcheckNone is the Test[0] value that disables an image's healthcheck,
// matching Docker's "--no-healthcheck".
const HealthcheckNone = "NONE"

// DefaultHealthInterval, DefaultHealthTimeout and DefaultHealthRetries are what
// a healthcheck gets when the image or the user left them zero. They are
// Docker's defaults, so an image written for Docker behaves identically here.
const (
	DefaultHealthInterval = 30 * time.Second
	DefaultHealthTimeout  = 30 * time.Second
	DefaultHealthRetries  = 3
)

// MergeImageConfig folds an image's configuration into a container's, with the
// image always losing to an explicit user value.
//
// The one place that is not a plain "user wins" is entrypoint and command,
// where Docker's rule is subtler and catches people out: supplying an
// entrypoint and no command clears the image's command, because the image's
// command was written as arguments to the image's entrypoint and is meaningless
// once the entrypoint is replaced. The merged record therefore holds exactly
// the argv the container will run, which is what "hull inspect" should show.
//
// The result is a new value; neither input is mutated.
func MergeImageConfig(user types.ContainerConfig, img *types.Image) (types.ContainerConfig, error) {
	out := user
	out.Env = append([]string(nil), user.Env...)
	out.Cmd = append([]string(nil), user.Cmd...)
	out.Entrypoint = append([]string(nil), user.Entrypoint...)
	out.Labels = copyStringMap(user.Labels)
	out.ExposedPorts = copySet(user.ExposedPorts)
	out.Volumes = copySet(user.Volumes)
	if user.Healthcheck != nil {
		hc := *user.Healthcheck
		hc.Test = append([]string(nil), user.Healthcheck.Test...)
		out.Healthcheck = &hc
	}
	if img == nil {
		return out, nil
	}
	ic := img.Config

	env, err := bundle.MergeEnv(ic.Env, user.Env)
	if err != nil {
		return types.ContainerConfig{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	// An empty result is recorded as nil rather than an empty slice, so a
	// container with no environment round-trips through JSON unchanged.
	if len(env) == 0 {
		env = nil
	}
	out.Env = env

	// Entrypoint and command, by Docker's rule.
	entSpecified := len(user.Entrypoint) > 0
	cmdSpecified := len(user.Cmd) > 0
	switch {
	case entSpecified && cmdSpecified:
		// Both given: nothing from the image applies.
	case entSpecified:
		out.Cmd = nil
	case cmdSpecified:
		out.Entrypoint = append([]string(nil), ic.Entrypoint...)
	default:
		out.Entrypoint = append([]string(nil), ic.Entrypoint...)
		out.Cmd = append([]string(nil), ic.Cmd...)
	}

	if out.User == "" {
		out.User = ic.User
	}
	if out.WorkingDir == "" {
		out.WorkingDir = ic.WorkingDir
	}
	if out.StopSignal == "" {
		out.StopSignal = ic.StopSignal
	}

	// Exposed ports and image VOLUME declarations are unions: an image that
	// exposes 80 and a user that publishes 443 means both are exposed.
	out.ExposedPorts = unionSets(ic.ExposedPorts, out.ExposedPorts)
	out.Volumes = unionSets(ic.Volumes, out.Volumes)

	// Labels: the image supplies the base, the user overrides key by key.
	out.Labels = mergeLabels(ic.Labels, user.Labels)

	if out.Healthcheck == nil && ic.Healthcheck != nil {
		hc := *ic.Healthcheck
		hc.Test = append([]string(nil), ic.Healthcheck.Test...)
		out.Healthcheck = &hc
	}
	out.Healthcheck = normalizeHealthcheck(out.Healthcheck)
	return out, nil
}

// normalizeHealthcheck fills in the defaults a healthcheck is entitled to and
// drops one that is disabled or has no test at all, so the health worker never
// has to guess.
func normalizeHealthcheck(hc *types.Healthcheck) *types.Healthcheck {
	if hc == nil || len(hc.Test) == 0 {
		return nil
	}
	switch strings.ToUpper(hc.Test[0]) {
	case HealthcheckNone:
		return nil
	case "CMD", "CMD-SHELL":
		if len(hc.Test) < 2 {
			return nil
		}
	}
	out := *hc
	out.Test = append([]string(nil), hc.Test...)
	if out.Interval <= 0 {
		out.Interval = DefaultHealthInterval
	}
	if out.Timeout <= 0 {
		out.Timeout = DefaultHealthTimeout
	}
	if out.Retries <= 0 {
		out.Retries = DefaultHealthRetries
	}
	if out.StartPeriod < 0 {
		out.StartPeriod = 0
	}
	return &out
}

// HealthcheckCommand turns a healthcheck Test into the argv to exec inside the
// container, applying the image's SHELL for the CMD-SHELL form.
//
// The four shapes Docker defines are:
//
//	["NONE"]                 disabled, handled before this is called
//	["CMD", "curl", "-f", …] exec form, run directly
//	["CMD-SHELL", "…"]       run through the image's shell
//	["…"]                    legacy bare string, treated as CMD-SHELL
func HealthcheckCommand(hc *types.Healthcheck, shell []string) ([]string, error) {
	if hc == nil || len(hc.Test) == 0 {
		return nil, fmt.Errorf("%w: the container has no healthcheck", ErrInvalid)
	}
	if len(shell) == 0 {
		shell = []string{"/bin/sh", "-c"}
	}
	switch strings.ToUpper(hc.Test[0]) {
	case HealthcheckNone:
		return nil, fmt.Errorf("%w: the healthcheck is disabled", ErrInvalid)
	case "CMD":
		if len(hc.Test) < 2 {
			return nil, fmt.Errorf("%w: healthcheck CMD has no command", ErrInvalid)
		}
		return append([]string(nil), hc.Test[1:]...), nil
	case "CMD-SHELL":
		if len(hc.Test) < 2 {
			return nil, fmt.Errorf("%w: healthcheck CMD-SHELL has no command", ErrInvalid)
		}
		return append(append([]string(nil), shell...), strings.Join(hc.Test[1:], " ")), nil
	default:
		return append(append([]string(nil), shell...), strings.Join(hc.Test, " ")), nil
	}
}

// unionSets merges two set-shaped maps, returning nil when both are empty.
func unionSets(base, over map[string]struct{}) map[string]struct{} {
	if len(base) == 0 && len(over) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(base)+len(over))
	for k := range base {
		out[k] = struct{}{}
	}
	for k := range over {
		out[k] = struct{}{}
	}
	return out
}

// mergeLabels layers user labels over image labels.
func mergeLabels(base, over map[string]string) map[string]string {
	if len(base) == 0 && len(over) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

// applyHostDefaults fills in the host-side settings hull guarantees: a log
// driver, a network mode and a runtime name.
func (e *Engine) applyHostDefaults(host types.HostConfig) types.HostConfig {
	if host.LogConfig.Type == "" {
		host.LogConfig = e.cfg.LogConfig
	}
	if host.NetworkMode == "" {
		host.NetworkMode = "bridge"
	}
	if host.Runtime == "" {
		host.Runtime = e.runtimeName
	}
	return host
}

// publishAllBindings synthesises a binding for every exposed port when
// --publish-all was asked for, leaving the host port empty so the kernel
// chooses a free one.
func publishAllBindings(cfg types.ContainerConfig, existing map[string][]types.PortBinding) map[string][]types.PortBinding {
	out := make(map[string][]types.PortBinding, len(cfg.ExposedPorts)+len(existing))
	for spec, list := range existing {
		out[spec] = list
	}
	for spec := range cfg.ExposedPorts {
		if _, ok := out[spec]; !ok {
			out[spec] = []types.PortBinding{{HostIP: "0.0.0.0"}}
		}
	}
	return out
}
