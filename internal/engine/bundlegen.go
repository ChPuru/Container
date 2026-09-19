package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rahuldhali/hull/internal/bundle"
	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	"github.com/rahuldhali/hull/internal/types"
)

// usernsIDCount is the size of the uid and gid range each container gets when
// hull runs it in its own user namespace. 65536 is the conventional size, and
// is what /etc/subuid entries are usually allocated in.
const usernsIDCount = 65536

// sandboxFiles are the three files the network manager renders per container
// and the bundle bind-mounts into it.
//
// They are bound from a stable per-container inode rather than from the file
// the manager writes, because the manager replaces that file by rename when
// the container's address is allocated, and a rename breaks a bind mount
// silently: the container would keep seeing the pre-allocation contents
// forever. The ".mnt" copies are written in place, so the inode the container
// holds is the one that changes.
var sandboxFiles = []struct {
	// src is the file network.ConfigureSandbox writes.
	src string
	// mnt is the stable copy that is actually bind-mounted.
	mnt string
	// dest is where it appears inside the container.
	dest string
}{
	{"hostname", "hostname.mnt", "/etc/hostname"},
	{"hosts", "hosts.mnt", "/etc/hosts"},
	{"resolv.conf", "resolv.conf.mnt", "/etc/resolv.conf"},
}

// syncSandboxFiles copies the network manager's rendered hostname, hosts and
// resolv.conf onto the stable inodes the bundle binds, in place.
//
// It is called once before the container is created and again after its
// address is allocated, and the second call is why the copy has to be in place
// rather than atomic: an already-mounted bind follows the inode, not the name.
func (e *Engine) syncSandboxFiles(id string) error {
	dir := e.containerDir(id)
	for _, f := range sandboxFiles {
		data, err := os.ReadFile(filepath.Join(dir, f.src))
		if err != nil {
			if os.IsNotExist(err) {
				data = nil
			} else {
				return fmt.Errorf("engine: read %s for %s: %w", f.src, idShort(id), err)
			}
		}
		// os.WriteFile truncates the existing file instead of replacing it,
		// which is exactly what a live bind mount needs.
		if err := os.WriteFile(filepath.Join(dir, f.mnt), data, 0o644); err != nil {
			return fmt.Errorf("engine: write %s for %s: %w", f.mnt, idShort(id), err)
		}
	}
	return nil
}

// bundleView builds the container and image copies bundle.Generate is given.
//
// The volume manager is the single authority on what gets mounted where: by
// the time a bundle is generated it has already folded -v, --mount, --tmpfs
// and the image's VOLUME set into one ordered list of concrete host paths.
// Handing bundle the original request as well would make it resolve the same
// mounts a second time, from stale inputs, so the view clears them and passes
// only the resolved list.
func (e *Engine) bundleView(c *types.Container, img *types.Image) (*types.Container, *types.Image) {
	cc := *c
	cc.Config = copyContainerConfig(c.Config)
	cc.HostConfig = copyHostConfig(c.HostConfig)
	cc.HostConfig.Binds = nil
	cc.HostConfig.Tmpfs = nil
	cc.Config.Volumes = nil

	mounts := make([]types.Mount, 0, len(c.HostConfig.Mounts)+len(sandboxFiles))
	for _, m := range c.HostConfig.Mounts {
		if m.Type == "volume" {
			// Source is already the volume's host _data directory, so the
			// spec mount is an ordinary bind. Keeping type "volume" would
			// send bundle looking for a VolumePaths entry it has no reason
			// to have.
			m.Type = "bind"
		}
		mounts = append(mounts, m)
	}
	if c.HostConfig.NetworkMode != "host" {
		dir := e.containerDir(c.ID)
		for _, f := range sandboxFiles {
			mounts = append(mounts, types.Mount{
				Type:   "bind",
				Source: filepath.Join(dir, f.mnt),
				Target: f.dest,
			})
		}
	}
	cc.HostConfig.Mounts = mounts

	ic := *img
	ic.Config = copyImageConfig(img.Config)
	ic.Config.Volumes = nil
	return &cc, &ic
}

// bundleOptions assembles the host-side facts bundle cannot derive from the
// container record.
func (e *Engine) bundleOptions(c *types.Container) bundle.Options {
	opts := bundle.Options{
		RootFS:      c.RootFS,
		BundleDir:   e.containerDir(c.ID),
		CgroupsPath: cgroupRel(c.ID),
		Hostname:    c.Config.Hostname,
		Init:        c.HostConfig.Init,
		InitPath:    e.cfg.InitBinary,
		Features:    e.bundleFeat,
		// The runtime refuses a spec version it does not know, and says so
		// uselessly. The engine writes the highest version the installed
		// runtime admits to understanding, never simply the newest.
		SpecVersion: e.specVersion,
		Annotations: map[string]string{},
	}
	if ns := e.usernsFor(c.HostConfig); ns != nil {
		opts.UserNS = ns
	}
	return opts
}

// usernsFor decides whether this container runs in its own user namespace.
//
// hull wants one for every container, but it refuses to invent a mapping: a
// private namespace needs a delegated subordinate id range, and mapping a
// container onto host uids while claiming it is isolated would be worse than
// not isolating it at all. When there is no usable range the container runs in
// the host user namespace and the decision is recorded as a warning.
func (e *Engine) usernsFor(host types.HostConfig) *bundle.UserNS {
	if strings.EqualFold(host.UsernsMode, "host") || host.Privileged {
		return nil
	}
	if e.host == nil || !e.host.Namespaces.User {
		return nil
	}
	start, count, ok := parseSubIDRange(e.host.Namespaces.SubuidRange)
	if !ok {
		return nil
	}
	gstart, gcount, gok := parseSubIDRange(e.host.Namespaces.SubgidRange)
	if !gok {
		gstart, gcount = start, count
	}
	if count > usernsIDCount {
		count = usernsIDCount
	}
	if gcount > usernsIDCount {
		gcount = usernsIDCount
	}
	return &bundle.UserNS{
		UIDMappings: []runtimespec.LinuxIDMapping{{ContainerID: 0, HostID: uint32(start), Size: uint32(count)}},
		GIDMappings: []runtimespec.LinuxIDMapping{{ContainerID: 0, HostID: uint32(gstart), Size: uint32(gcount)}},
	}
}

// parseSubIDRange reads an /etc/subuid style "start:count" pair.
func parseSubIDRange(s string) (start, count int, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	b, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || a <= 0 || b <= 0 {
		return 0, 0, false
	}
	return a, b, true
}

// generateBundle writes the container's config.json and returns the warnings
// bundle raised.
//
// Those warnings matter: bundle reports rather than fails when a resource
// limit cannot be enforced on this host's hybrid cgroups, so a container runs
// unlimited instead of refusing to start. If the warnings stop here the user
// silently gets an unlimited container, which is why they are persisted and
// surfaced through Warnings.
func (e *Engine) generateBundle(c *types.Container, img *types.Image) ([]string, error) {
	cc, ic := e.bundleView(c, img)
	spec, warnings, err := bundle.Generate(cc, ic, e.bundleOptions(c))
	if err != nil {
		return warnings, fmt.Errorf("engine: generate the OCI bundle for %s: %w", idShort(c.ID), err)
	}
	if err := bundle.Write(spec, e.containerDir(c.ID)); err != nil {
		return warnings, fmt.Errorf("engine: write the OCI bundle for %s: %w", idShort(c.ID), err)
	}
	return warnings, nil
}

// copyContainerConfig deep-copies a container config.
func copyContainerConfig(in types.ContainerConfig) types.ContainerConfig {
	out := in
	out.Env = append([]string(nil), in.Env...)
	out.Cmd = append([]string(nil), in.Cmd...)
	out.Entrypoint = append([]string(nil), in.Entrypoint...)
	out.Labels = copyStringMap(in.Labels)
	out.ExposedPorts = copySet(in.ExposedPorts)
	out.Volumes = copySet(in.Volumes)
	if in.StopTimeout != nil {
		v := *in.StopTimeout
		out.StopTimeout = &v
	}
	if in.Healthcheck != nil {
		hc := *in.Healthcheck
		hc.Test = append([]string(nil), in.Healthcheck.Test...)
		out.Healthcheck = &hc
	}
	return out
}

// copyHostConfig deep-copies a host config.
func copyHostConfig(in types.HostConfig) types.HostConfig {
	out := in
	out.Binds = append([]string(nil), in.Binds...)
	out.Mounts = append([]types.Mount(nil), in.Mounts...)
	out.DNS = append([]string(nil), in.DNS...)
	out.DNSSearch = append([]string(nil), in.DNSSearch...)
	out.ExtraHosts = append([]string(nil), in.ExtraHosts...)
	out.CapAdd = append([]string(nil), in.CapAdd...)
	out.CapDrop = append([]string(nil), in.CapDrop...)
	out.SecurityOpt = append([]string(nil), in.SecurityOpt...)
	out.GroupAdd = append([]string(nil), in.GroupAdd...)
	out.Ulimits = append([]types.Ulimit(nil), in.Ulimits...)
	out.Devices = append([]types.DeviceMapping(nil), in.Devices...)
	out.Sysctls = copyStringMap(in.Sysctls)
	out.Tmpfs = copyStringMap(in.Tmpfs)
	out.LogConfig.Config = copyStringMap(in.LogConfig.Config)
	if in.PidsLimit != nil {
		v := *in.PidsLimit
		out.PidsLimit = &v
	}
	if len(in.PortBindings) > 0 {
		out.PortBindings = make(map[string][]types.PortBinding, len(in.PortBindings))
		for k, v := range in.PortBindings {
			out.PortBindings[k] = append([]types.PortBinding(nil), v...)
		}
	}
	return out
}

// copyContainer deep-copies a container record so a caller can never mutate
// what the engine persisted.
func copyContainer(c *types.Container) *types.Container {
	if c == nil {
		return nil
	}
	out := *c
	out.Config = copyContainerConfig(c.Config)
	out.HostConfig = copyHostConfig(c.HostConfig)
	out.NetworkSettings = copyNetworkSettings(c.NetworkSettings)
	if c.Health != nil {
		h := *c.Health
		h.Log = append([]types.HealthLog(nil), c.Health.Log...)
		out.Health = &h
	}
	return &out
}

// copyNetworkSettings deep-copies a container's network view.
func copyNetworkSettings(in types.NetworkSettings) types.NetworkSettings {
	out := in
	if len(in.Networks) > 0 {
		out.Networks = make(map[string]types.EndpointSettings, len(in.Networks))
		for k, v := range in.Networks {
			v.Aliases = append([]string(nil), v.Aliases...)
			v.DNSNames = append([]string(nil), v.DNSNames...)
			out.Networks[k] = v
		}
	}
	if len(in.Ports) > 0 {
		out.Ports = make(map[string][]types.PortBinding, len(in.Ports))
		for k, v := range in.Ports {
			out.Ports[k] = append([]types.PortBinding(nil), v...)
		}
	}
	return out
}
