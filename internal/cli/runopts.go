package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rahuldhali/hull/internal/client"
)

// runOptions is the whole of "hull run"'s flag surface, shared with
// "hull create" because the two differ only in what happens after the
// container exists.
type runOptions struct {
	// process
	detach      bool
	interactive bool
	tty         bool
	name        string
	hostname    string
	domainname  string
	user        string
	workdir     string
	entrypoint  string
	env         []string
	envFile     []string
	labels      []string
	labelFile   []string
	stopSignal  string
	stopTimeout int
	detachKeys  string
	attach      []string
	sigProxy    bool
	initProc    bool
	autoRemove  bool

	// storage
	volumes  []string
	mounts   []string
	tmpfs    []string
	readOnly bool
	shmSize  string

	// network
	publish      []string
	publishAll   bool
	expose       []string
	network      string
	networkAlias []string
	dns          []string
	dnsSearch    []string
	dnsOption    []string
	addHost      []string

	// resources
	memory            string
	memorySwap        string
	memoryReservation string
	cpus              float64
	cpuShares         int64
	cpuPeriod         int64
	cpuQuota          int64
	cpusetCpus        string
	cpusetMems        string
	blkioWeight       int
	pidsLimit         int64
	ulimits           []string
	oomScoreAdj       int

	// security and isolation
	privileged  bool
	capAdd      []string
	capDrop     []string
	securityOpt []string
	sysctls     []string
	devices     []string
	groupAdd    []string
	usernsMode  string
	isolation   string
	runtime     string

	// health
	healthCmd         string
	healthInterval    time.Duration
	healthTimeout     time.Duration
	healthStartPeriod time.Duration
	healthRetries     int
	noHealthcheck     bool

	// lifecycle
	restart   string
	logDriver string
	logOpt    []string
	pull      string
	platform  string

	// hull's own
	explain    bool
	budget     string
	idleFreeze time.Duration
}

// registerRunFlags declares every run and create flag on fs.
//
// The spellings are Docker's wherever Docker has one, so muscle memory
// transfers; the four hull-only flags are the ones docs/CLI.md calls out.
func registerRunFlags(fs *FlagSet, o *runOptions, withRunOnly bool) {
	fs.BoolVar(&o.interactive, "interactive", "i", false, "Keep STDIN open even if not attached")
	fs.BoolVar(&o.tty, "tty", "t", false, "Allocate a pseudo-TTY")
	fs.StringVar(&o.name, "name", "", "", "Assign a name to the container")
	fs.StringVar(&o.hostname, "hostname", "h", "", "Container host name")
	fs.StringVar(&o.domainname, "domainname", "", "", "Container NIS domain name")
	fs.StringVar(&o.user, "user", "u", "", "Username or UID (format: <name|uid>[:<group|gid>])")
	fs.StringVar(&o.workdir, "workdir", "w", "", "Working directory inside the container")
	fs.StringVar(&o.entrypoint, "entrypoint", "", "", "Overwrite the default ENTRYPOINT of the image")
	fs.StringSliceVar(&o.env, "env", "e", "Set environment variables")
	fs.StringSliceVar(&o.envFile, "env-file", "", "Read in a file of environment variables")
	fs.StringSliceVar(&o.labels, "label", "l", "Set metadata on a container")
	fs.StringSliceVar(&o.labelFile, "label-file", "", "Read in a line-delimited file of labels")
	fs.StringVar(&o.stopSignal, "stop-signal", "", "", "Signal to stop the container")
	fs.IntVar(&o.stopTimeout, "stop-timeout", "", 0, "Timeout (in seconds) to stop a container")
	fs.StringVar(&o.detachKeys, "detach-keys", "", "", "Override the key sequence for detaching a container")
	fs.BoolVar(&o.initProc, "init", "", false, "Run an init inside the container that forwards signals and reaps processes")

	fs.StringSliceVar(&o.volumes, "volume", "v", "Bind mount a volume")
	fs.StringSliceVar(&o.mounts, "mount", "", "Attach a filesystem mount to the container")
	fs.StringSliceVar(&o.tmpfs, "tmpfs", "", "Mount a tmpfs directory")
	fs.BoolVar(&o.readOnly, "read-only", "", false, "Mount the container's root filesystem as read only")
	fs.StringVar(&o.shmSize, "shm-size", "", "", "Size of /dev/shm")

	fs.StringSliceVar(&o.publish, "publish", "p", "Publish a container's port(s) to the host")
	fs.BoolVar(&o.publishAll, "publish-all", "P", false, "Publish all exposed ports to random ports")
	fs.StringSliceVar(&o.expose, "expose", "", "Expose a port or a range of ports")
	fs.StringVar(&o.network, "network", "", "", "Connect a container to a network")
	fs.StringSliceVar(&o.networkAlias, "network-alias", "", "Add network-scoped alias for the container")
	fs.StringSliceVar(&o.dns, "dns", "", "Set custom DNS servers")
	fs.StringSliceVar(&o.dnsSearch, "dns-search", "", "Set custom DNS search domains")
	fs.StringSliceVar(&o.dnsOption, "dns-option", "", "Set DNS options")
	fs.StringSliceVar(&o.addHost, "add-host", "", "Add a custom host-to-IP mapping (host:ip)")

	fs.StringVar(&o.memory, "memory", "m", "", "Memory limit")
	fs.StringVar(&o.memorySwap, "memory-swap", "", "", "Swap limit equal to memory plus swap: -1 to enable unlimited swap")
	fs.StringVar(&o.memoryReservation, "memory-reservation", "", "", "Memory soft limit")
	fs.Float64Var(&o.cpus, "cpus", "", 0, "Number of CPUs")
	fs.Int64Var(&o.cpuShares, "cpu-shares", "c", 0, "CPU shares (relative weight)")
	fs.Int64Var(&o.cpuPeriod, "cpu-period", "", 0, "Limit CPU CFS (Completely Fair Scheduler) period")
	fs.Int64Var(&o.cpuQuota, "cpu-quota", "", 0, "Limit CPU CFS (Completely Fair Scheduler) quota")
	fs.StringVar(&o.cpusetCpus, "cpuset-cpus", "", "", "CPUs in which to allow execution (0-3, 0,1)")
	fs.StringVar(&o.cpusetMems, "cpuset-mems", "", "", "MEMs in which to allow execution (0-3, 0,1)")
	fs.IntVar(&o.blkioWeight, "blkio-weight", "", 0, "Block IO (relative weight), between 10 and 1000")
	fs.Int64Var(&o.pidsLimit, "pids-limit", "", 0, "Tune container pids limit (set -1 for unlimited)")
	fs.StringSliceVar(&o.ulimits, "ulimit", "", "Ulimit options")
	fs.IntVar(&o.oomScoreAdj, "oom-score-adj", "", 0, "Tune host's OOM preferences (-1000 to 1000)")

	fs.BoolVar(&o.privileged, "privileged", "", false, "Give extended privileges to this container")
	fs.StringSliceVar(&o.capAdd, "cap-add", "", "Add Linux capabilities")
	fs.StringSliceVar(&o.capDrop, "cap-drop", "", "Drop Linux capabilities")
	fs.StringSliceVar(&o.securityOpt, "security-opt", "", "Security options")
	fs.StringSliceVar(&o.sysctls, "sysctl", "", "Sysctl options")
	fs.StringSliceVar(&o.devices, "device", "", "Add a host device to the container")
	fs.StringSliceVar(&o.groupAdd, "group-add", "", "Add additional groups to join")
	fs.StringVar(&o.usernsMode, "userns", "", "", "User namespace to use (host or private)")
	fs.StringVar(&o.runtime, "runtime", "", "", "Runtime to use for this container (hull or crun)")

	fs.StringVar(&o.healthCmd, "health-cmd", "", "", "Command to run to check health")
	fs.DurationVar(&o.healthInterval, "health-interval", "", 0, "Time between running the check")
	fs.DurationVar(&o.healthTimeout, "health-timeout", "", 0, "Maximum time to allow one check to run")
	fs.DurationVar(&o.healthStartPeriod, "health-start-period", "", 0, "Start period for the container to initialize before counting retries")
	fs.IntVar(&o.healthRetries, "health-retries", "", 0, "Consecutive failures needed to report unhealthy")
	fs.BoolVar(&o.noHealthcheck, "no-healthcheck", "", false, "Disable any container-specified HEALTHCHECK")

	fs.StringVar(&o.restart, "restart", "", "", "Restart policy to apply when a container exits")
	fs.StringVar(&o.logDriver, "log-driver", "", "", "Logging driver for the container")
	fs.StringSliceVar(&o.logOpt, "log-opt", "", "Log driver options")
	fs.StringVar(&o.pull, "pull", "", "missing", `Pull image before running ("always", "missing", "never")`)
	fs.StringVar(&o.platform, "platform", "", "", "Set platform if server is multi-platform capable")

	// hull's own flags, prefixed in spirit by being absent from Docker.
	fs.StringVar(&o.isolation, "isolation", "", "", "Isolation tier for this container (userns, host, gvisor)")
	fs.BoolVar(&o.explain, "explain", "", false, "Narrate every kernel step the engine takes")
	fs.StringVar(&o.budget, "budget", "", "", "Soft resource budget, e.g. mem=2G,cpu=2: warn instead of OOM-killing")
	fs.DurationVar(&o.idleFreeze, "idle-freeze", "", 0, "Freeze this container after it has been idle this long")

	if withRunOnly {
		fs.BoolVar(&o.detach, "detach", "d", false, "Run container in background and print container ID")
		fs.BoolVar(&o.autoRemove, "rm", "", false, "Automatically remove the container when it exits")
		fs.StringSliceVar(&o.attach, "attach", "a", "Attach to STDIN, STDOUT or STDERR")
		fs.BoolVar(&o.sigProxy, "sig-proxy", "", true, "Proxy received signals to the process")
	}
}

// buildCreateRequest turns parsed flags into the create body the engine wants.
//
// Everything that can be rejected locally is rejected here, with the offending
// spec quoted, because a round trip to the engine to be told "invalid port"
// helps nobody.
func (o *runOptions) buildCreateRequest(env *Env, image string, cmd []string) (client.ContainerCreateRequest, error) {
	cfg := client.Config{
		Hostname:     o.hostname,
		Domainname:   o.domainname,
		User:         o.user,
		Image:        image,
		WorkingDir:   o.workdir,
		Tty:          o.tty,
		OpenStdin:    o.interactive,
		StdinOnce:    o.interactive,
		StopSignal:   o.stopSignal,
		ExposedPorts: map[string]struct{}{},
		Labels:       map[string]string{},
	}
	if len(cmd) > 0 {
		cfg.Cmd = cmd
	}
	if o.entrypoint != "" {
		cfg.Entrypoint = []string{o.entrypoint}
	}
	if o.stopTimeout > 0 {
		t := o.stopTimeout
		cfg.StopTimeout = &t
	}

	// Environment: files first, so an explicit -e wins over an --env-file.
	for _, path := range o.envFile {
		vars, err := ReadEnvFile(path)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		cfg.Env = append(cfg.Env, vars...)
	}
	cfg.Env = append(cfg.Env, expandEnvFromHost(o.env)...)

	for _, path := range o.labelFile {
		vars, err := ReadLabelFile(path)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		for k, v := range ParseLabels(vars) {
			cfg.Labels[k] = v
		}
	}
	for k, v := range ParseLabels(o.labels) {
		cfg.Labels[k] = v
	}
	if len(cfg.Labels) == 0 {
		cfg.Labels = nil
	}

	// The host config is filled field by field rather than as one literal:
	// several of these knobs live in an embedded Resources block, and plain
	// assignment works either way.
	var host client.HostConfig
	host.NetworkMode = o.network
	host.PublishAllPorts = o.publishAll
	host.Privileged = o.privileged
	host.ReadonlyRootfs = o.readOnly
	host.CapAdd = o.capAdd
	host.CapDrop = o.capDrop
	host.SecurityOpt = o.securityOpt
	host.DNS = o.dns
	host.DNSSearch = o.dnsSearch
	host.DNSOptions = o.dnsOption
	host.GroupAdd = o.groupAdd
	host.UsernsMode = o.usernsMode
	host.Isolation = o.isolation
	host.Runtime = o.runtime
	host.AutoRemove = o.autoRemove
	host.HullExplain = o.explain
	host.HullBudget = o.budget
	host.OomScoreAdj = o.oomScoreAdj
	host.CpusetCpus = o.cpusetCpus
	host.CpusetMems = o.cpusetMems
	host.CPUShares = o.cpuShares
	host.CPUPeriod = o.cpuPeriod
	host.CPUQuota = o.cpuQuota
	host.BlkioWeight = uint16(o.blkioWeight)
	if o.initProc {
		init := true
		host.Init = &init
	}
	if o.idleFreeze != 0 {
		host.HullIdleFreeze = o.idleFreeze.String()
	}
	if o.logDriver != "" || len(o.logOpt) > 0 {
		host.LogConfig = client.LogConfig{Type: o.logDriver, Config: ParseLabels(o.logOpt)}
	}

	// Ports.
	for _, spec := range o.publish {
		exposed, bindings, err := ParsePublish(spec)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		for _, port := range exposed {
			cfg.ExposedPorts[port] = struct{}{}
		}
		if host.PortBindings == nil {
			host.PortBindings = map[string][]client.PortBinding{}
		}
		for port, binds := range bindings {
			host.PortBindings[port] = append(host.PortBindings[port], binds...)
		}
	}
	for _, spec := range o.expose {
		ports, err := ParseExpose(spec)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		for _, port := range ports {
			cfg.ExposedPorts[port] = struct{}{}
		}
	}
	if len(cfg.ExposedPorts) == 0 {
		cfg.ExposedPorts = nil
	}

	// Storage.
	for _, spec := range o.volumes {
		bind, err := ParseBind(spec)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		if strings.Contains(bind, ":") {
			host.Binds = append(host.Binds, bind)
			continue
		}
		// A single path is an anonymous volume, which Docker carries in
		// Config.Volumes rather than in Binds.
		if cfg.Volumes == nil {
			cfg.Volumes = map[string]struct{}{}
		}
		cfg.Volumes[bind] = struct{}{}
	}
	for _, spec := range o.mounts {
		m, err := ParseMount(spec)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		host.Mounts = append(host.Mounts, m)
	}
	for _, spec := range o.tmpfs {
		path, opts, err := ParseTmpfs(spec)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		if host.Tmpfs == nil {
			host.Tmpfs = map[string]string{}
		}
		host.Tmpfs[path] = opts
	}
	if o.shmSize != "" {
		n, err := ParseSize(o.shmSize)
		if err != nil {
			return client.ContainerCreateRequest{}, fmt.Errorf("invalid --shm-size %q: %w", o.shmSize, err)
		}
		host.ShmSize = n
	}

	// Devices, sysctls and ulimits.
	for _, spec := range o.devices {
		d, err := ParseDevice(spec)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		host.Devices = append(host.Devices, d)
	}
	if len(o.sysctls) > 0 {
		host.Sysctls = ParseLabels(o.sysctls)
	}
	for _, spec := range o.ulimits {
		u, err := ParseUlimit(spec)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		host.Ulimits = append(host.Ulimits, u)
	}
	for _, spec := range o.addHost {
		h, err := ParseAddHost(spec)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		host.ExtraHosts = append(host.ExtraHosts, h)
	}

	// Resources.
	if o.memory != "" {
		n, err := ParseSize(o.memory)
		if err != nil {
			return client.ContainerCreateRequest{}, fmt.Errorf("invalid --memory %q: %w", o.memory, err)
		}
		host.Memory = n
	}
	if o.memoryReservation != "" {
		n, err := ParseSize(o.memoryReservation)
		if err != nil {
			return client.ContainerCreateRequest{}, fmt.Errorf("invalid --memory-reservation %q: %w", o.memoryReservation, err)
		}
		host.MemoryReservation = n
	}
	if o.memorySwap != "" {
		if strings.TrimSpace(o.memorySwap) == "-1" {
			host.MemorySwap = -1
		} else {
			n, err := ParseSize(o.memorySwap)
			if err != nil {
				return client.ContainerCreateRequest{}, fmt.Errorf("invalid --memory-swap %q: %w", o.memorySwap, err)
			}
			host.MemorySwap = n
		}
	}
	if o.cpus > 0 {
		host.NanoCPUs = int64(o.cpus * 1e9)
	}
	if o.pidsLimit != 0 {
		limit := o.pidsLimit
		host.PidsLimit = &limit
	}
	if o.restart != "" {
		rp, err := ParseRestartPolicy(o.restart)
		if err != nil {
			return client.ContainerCreateRequest{}, err
		}
		host.RestartPolicy = rp
		if rp.Name != "" && rp.Name != "no" && o.autoRemove {
			return client.ContainerCreateRequest{}, Errorf("conflicting options: --rm and --restart cannot be used together")
		}
	}

	if hc := ParseHealthcheck(o.healthCmd, o.healthInterval, o.healthTimeout, o.healthStartPeriod, o.healthRetries, o.noHealthcheck); hc != nil {
		cfg.Healthcheck = hc
	}

	// Attachment. -a overrides the -i/-t defaults when it is given.
	cfg.AttachStdout, cfg.AttachStderr = true, true
	cfg.AttachStdin = o.interactive
	if len(o.attach) > 0 {
		cfg.AttachStdin, cfg.AttachStdout, cfg.AttachStderr = false, false, false
		for _, a := range o.attach {
			switch strings.ToLower(strings.TrimSpace(a)) {
			case "stdin":
				cfg.AttachStdin, cfg.OpenStdin = true, true
			case "stdout":
				cfg.AttachStdout = true
			case "stderr":
				cfg.AttachStderr = true
			default:
				return client.ContainerCreateRequest{}, Errorf("invalid --attach %q: want stdin, stdout or stderr", a)
			}
		}
	}
	if o.detach {
		cfg.AttachStdin, cfg.AttachStdout, cfg.AttachStderr = false, false, false
	}

	req := client.ContainerCreateRequest{Config: cfg, HostConfig: &host}
	if len(o.networkAlias) > 0 {
		if o.network == "" {
			return client.ContainerCreateRequest{}, Errorf("--network-alias needs --network")
		}
		req.NetworkingConfig = &client.NetworkingConfig{
			EndpointsConfig: map[string]*client.EndpointSettings{
				o.network: {Aliases: o.networkAlias},
			},
		}
	}
	env.Debugf("create request built for image %s", image)
	return req, nil
}

// expandEnvFromHost fills in a bare "-e NAME" from the caller's own
// environment, which is the shorthand Docker supports and compose files rely
// on. A name that is not set in the environment is dropped rather than passed
// through empty.
func expandEnvFromHost(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.Contains(e, "=") {
			out = append(out, e)
			continue
		}
		if v, ok := os.LookupEnv(e); ok {
			out = append(out, e+"="+v)
		}
	}
	return out
}

// pullPolicy validates the --pull value.
func pullPolicy(v string) (string, error) {
	switch v {
	case "", "missing", "always", "never":
		return v, nil
	default:
		return "", Errorf(`invalid --pull %q: want "always", "missing" or "never"`, v)
	}
}
