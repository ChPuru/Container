package api

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/ChPuru/hull/internal/engine"
	"github.com/ChPuru/hull/internal/events"
	"github.com/ChPuru/hull/internal/types"
	"github.com/ChPuru/hull/internal/version"
)

// pingHeaders sets the headers every client reads before it does anything
// else. Version negotiation happens here, not in /version: a client that
// cannot parse these gives up before the first real request.
func (s *Server) pingHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Api-Version", s.version.String())
	h.Set("Docker-Experimental", "false")
	h.Set("OSType", "linux")
	h.Set("Builder-Version", s.builderVersion())
	h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
}

// builderVersion tells clients which builder to drive.
//
// "2" routes docker build through buildx and the /grpc and /session
// endpoints; "1" makes it POST the tar context to /build. hull answers
// honestly: with no buildkitd there is nothing behind /grpc, and a client
// that was told "2" would fail in a far more confusing place than the
// actionable 501 /build returns.
func (s *Server) builderVersion() string {
	if s.buildKitAvailable() {
		return "2"
	}
	return "1"
}

// getPing answers GET /_ping.
func (s *Server) getPing(w http.ResponseWriter, _ *http.Request) error {
	s.pingHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "2")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
	return nil
}

// headPing answers HEAD /_ping, which carries the headers and no body.
func (s *Server) headPing(w http.ResponseWriter, _ *http.Request) error {
	s.pingHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
	return nil
}

// VersionComponent is one entry of /version's Components array.
type VersionComponent struct {
	// Name is the component, e.g. "Engine".
	Name string `json:"Name"`
	// Version is its version string.
	Version string `json:"Version"`
	// Details is free-form metadata the CLI prints.
	Details map[string]string `json:"Details,omitempty"`
}

// VersionPlatform names the product a daemon belongs to.
type VersionPlatform struct {
	// Name is the platform name the CLI prints in its header.
	Name string `json:"Name"`
}

// VersionResponse is the body of GET /version.
type VersionResponse struct {
	// Platform names the product.
	Platform VersionPlatform `json:"Platform"`
	// Components lists the engine and its runtimes.
	Components []VersionComponent `json:"Components"`
	// Version is the daemon version clients gate features on.
	Version string `json:"Version"`
	// APIVersion and MinAPIVersion bound what this daemon serves.
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	// GitCommit, GoVersion, BuildTime and the platform fields describe the
	// build.
	GitCommit     string `json:"GitCommit"`
	GoVersion     string `json:"GoVersion"`
	Os            string `json:"Os"`
	Arch          string `json:"Arch"`
	KernelVersion string `json:"KernelVersion"`
	BuildTime     string `json:"BuildTime"`
	// Experimental is always false.
	Experimental bool `json:"Experimental"`
}

// getVersion answers GET /version.
func (s *Server) getVersion(w http.ResponseWriter, r *http.Request) error {
	info, err := s.backend.Info(r.Context())
	if err != nil {
		return err
	}
	resp := VersionResponse{
		Platform:      VersionPlatform{Name: "hull"},
		Version:       version.DockerVersion,
		APIVersion:    s.version.String(),
		MinAPIVersion: s.minVersion.String(),
		GitCommit:     version.Commit,
		GoVersion:     runtime.Version(),
		Os:            "linux",
		Arch:          runtime.GOARCH,
		KernelVersion: info.KernelVersion,
		BuildTime:     version.BuildDate,
		Components: []VersionComponent{
			{
				Name:    "Engine",
				Version: version.Version,
				Details: map[string]string{
					"ApiVersion":    s.version.String(),
					"MinAPIVersion": s.minVersion.String(),
					"GitCommit":     version.Commit,
					"GoVersion":     runtime.Version(),
					"Os":            "linux",
					"Arch":          runtime.GOARCH,
					"KernelVersion": info.KernelVersion,
					"BuildTime":     version.BuildDate,
					"Experimental":  "false",
					"Product":       "hull",
				},
			},
			{
				Name:    "Runtime",
				Version: info.RuntimeVersion,
				Details: map[string]string{
					"Name":       info.DefaultRuntime,
					"OCIVersion": info.OCIVersion,
				},
			},
		},
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// InfoRuntime is one runtime entry of /info's Runtimes map.
type InfoRuntime struct {
	// Path is the runtime binary, empty for hull's native driver.
	Path string `json:"path,omitempty"`
	// RuntimeArgs are extra arguments; hull passes none.
	RuntimeArgs []string `json:"runtimeArgs,omitempty"`
}

// InfoResponse is the body of GET /info, in Docker's shape.
//
// Only the fields real clients read are populated; the rest are present with
// their zero values because compose and the CLI both index into this document
// without checking whether a key exists.
type InfoResponse struct {
	// ID is the daemon's stable identity.
	ID string `json:"ID"`
	// The container population counters.
	Containers        int `json:"Containers"`
	ContainersRunning int `json:"ContainersRunning"`
	ContainersPaused  int `json:"ContainersPaused"`
	ContainersStopped int `json:"ContainersStopped"`
	// Images is how many images the local store holds.
	Images int `json:"Images"`
	// Driver and DriverStatus describe the storage driver.
	Driver       string      `json:"Driver"`
	DriverStatus [][2]string `json:"DriverStatus"`
	// DockerRootDir is hull's data directory under the name clients expect.
	DockerRootDir string `json:"DockerRootDir"`
	// Plugins names the built-in drivers.
	Plugins InfoPlugins `json:"Plugins"`
	// The feature booleans clients gate on.
	MemoryLimit       bool `json:"MemoryLimit"`
	SwapLimit         bool `json:"SwapLimit"`
	KernelMemoryTCP   bool `json:"KernelMemoryTCP"`
	CPUCfsPeriod      bool `json:"CpuCfsPeriod"`
	CPUCfsQuota       bool `json:"CpuCfsQuota"`
	CPUShares         bool `json:"CPUShares"`
	CPUSet            bool `json:"CPUSet"`
	PidsLimit         bool `json:"PidsLimit"`
	IPv4Forwarding    bool `json:"IPv4Forwarding"`
	BridgeNfIptables  bool `json:"BridgeNfIptables"`
	BridgeNfIP6tables bool `json:"BridgeNfIp6tables"`
	Debug             bool `json:"Debug"`
	OomKillDisable    bool `json:"OomKillDisable"`
	// NFd and NGoroutines are runtime counters the CLI prints.
	NFd         int `json:"NFd"`
	NGoroutines int `json:"NGoroutines"`
	// SystemTime is an RFC3339Nano instant.
	SystemTime string `json:"SystemTime"`
	// LoggingDriver, CgroupDriver and CgroupVersion describe the subsystems.
	LoggingDriver string `json:"LoggingDriver"`
	CgroupDriver  string `json:"CgroupDriver"`
	CgroupVersion string `json:"CgroupVersion"`
	// NEventsListener is how many /events clients are attached.
	NEventsListener int `json:"NEventsListener"`
	// The host description.
	KernelVersion      string `json:"KernelVersion"`
	OperatingSystem    string `json:"OperatingSystem"`
	OSVersion          string `json:"OSVersion"`
	OSType             string `json:"OSType"`
	Architecture       string `json:"Architecture"`
	NCPU               int    `json:"NCPU"`
	MemTotal           int64  `json:"MemTotal"`
	IndexServerAddress string `json:"IndexServerAddress"`
	// RegistryConfig is the mirror and insecure-registry policy.
	RegistryConfig InfoRegistryConfig `json:"RegistryConfig"`
	// GenericResources is a swarm field clients still read.
	GenericResources []string `json:"GenericResources"`
	// HTTPProxy, HTTPSProxy and NoProxy are the daemon's proxy settings.
	HTTPProxy  string `json:"HttpProxy"`
	HTTPSProxy string `json:"HttpsProxy"`
	NoProxy    string `json:"NoProxy"`
	// Name is the host name.
	Name string `json:"Name"`
	// Labels are daemon labels.
	Labels []string `json:"Labels"`
	// ExperimentalBuild and ServerVersion describe the build.
	ExperimentalBuild bool   `json:"ExperimentalBuild"`
	ServerVersion     string `json:"ServerVersion"`
	// Runtimes, DefaultRuntime and the init fields describe the runtime.
	Runtimes       map[string]InfoRuntime `json:"Runtimes"`
	DefaultRuntime string                 `json:"DefaultRuntime"`
	InitBinary     string                 `json:"InitBinary"`
	// Swarm is present and inactive; hull is single-host by design.
	Swarm InfoSwarm `json:"Swarm"`
	// LiveRestoreEnabled is always true: hull's containers are supervised by
	// shims that outlive the daemon.
	LiveRestoreEnabled bool `json:"LiveRestoreEnabled"`
	// Isolation is a Windows concept, empty here.
	Isolation string `json:"Isolation"`
	// InitCommit, RuncCommit and ContainerdCommit are build ids clients
	// print.
	InitCommit       InfoCommit `json:"InitCommit"`
	RuncCommit       InfoCommit `json:"RuncCommit"`
	ContainerdCommit InfoCommit `json:"ContainerdCommit"`
	// SecurityOptions lists the isolation features in effect.
	SecurityOptions []string `json:"SecurityOptions"`
	// Warnings are the host problems the operator should act on. On a stock
	// WSL host this is where the missing cgroup v2 delegation is reported,
	// and the CLI prints it unprompted.
	Warnings []string `json:"Warnings"`
	// DefaultAddressPools is the subnet pool container networks come from.
	DefaultAddressPools []InfoAddressPool `json:"DefaultAddressPools,omitempty"`
}

// InfoPlugins lists the built-in drivers.
type InfoPlugins struct {
	// Volume, Network, Authorization and Log are the driver names.
	Volume        []string `json:"Volume"`
	Network       []string `json:"Network"`
	Authorization []string `json:"Authorization"`
	Log           []string `json:"Log"`
}

// InfoRegistryConfig is the registry policy block.
type InfoRegistryConfig struct {
	// AllowNondistributableArtifactsCIDRs and the rest are libnetwork-era
	// fields clients read unconditionally.
	AllowNondistributableArtifactsCIDRs     []string                   `json:"AllowNondistributableArtifactsCIDRs"`
	AllowNondistributableArtifactsHostnames []string                   `json:"AllowNondistributableArtifactsHostnames"`
	InsecureRegistryCIDRs                   []string                   `json:"InsecureRegistryCIDRs"`
	IndexConfigs                            map[string]InfoIndexConfig `json:"IndexConfigs"`
	Mirrors                                 []string                   `json:"Mirrors"`
}

// InfoIndexConfig describes one registry index.
type InfoIndexConfig struct {
	// Name is the registry host.
	Name string `json:"Name"`
	// Mirrors are alternate hosts.
	Mirrors []string `json:"Mirrors"`
	// Secure reports TLS, Official the canonical Docker Hub index.
	Secure   bool `json:"Secure"`
	Official bool `json:"Official"`
}

// InfoSwarm is the inactive swarm block.
type InfoSwarm struct {
	// NodeID, NodeAddr and LocalNodeState report no swarm membership.
	NodeID   string `json:"NodeID"`
	NodeAddr string `json:"NodeAddr"`
	// LocalNodeState is always "inactive".
	LocalNodeState string `json:"LocalNodeState"`
	// ControlAvailable and Error complete the block.
	ControlAvailable bool   `json:"ControlAvailable"`
	Error            string `json:"Error"`
	// RemoteManagers is always null.
	RemoteManagers []string `json:"RemoteManagers"`
}

// InfoCommit is a component's build id.
type InfoCommit struct {
	// ID and Expected are the observed and expected commits.
	ID       string `json:"ID"`
	Expected string `json:"Expected"`
}

// InfoAddressPool is one default subnet pool.
type InfoAddressPool struct {
	// Base is the CIDR the pool carves from.
	Base string `json:"Base"`
	// Size is the prefix length of each carved subnet.
	Size int `json:"Size"`
}

// getInfo answers GET /info.
func (s *Server) getInfo(w http.ResponseWriter, r *http.Request) error {
	info, err := s.backend.Info(r.Context())
	if err != nil {
		return err
	}
	runtimes := map[string]InfoRuntime{}
	for _, name := range info.Runtimes {
		runtimes[name] = InfoRuntime{}
	}
	limitsWork := info.CgroupV2Delegated
	resp := InfoResponse{
		ID:                info.ID,
		Containers:        info.Containers,
		ContainersRunning: info.ContainersRunning,
		ContainersPaused:  info.ContainersPaused,
		ContainersStopped: info.ContainersStopped,
		Images:            info.Images,
		Driver:            info.Driver,
		DriverStatus:      info.DriverStatus,
		DockerRootDir:     info.DockerRootDir,
		Plugins: InfoPlugins{
			Volume:        stringsOrEmpty(info.Plugins.Volume),
			Network:       stringsOrEmpty(info.Plugins.Network),
			Authorization: nil,
			Log:           stringsOrEmpty(info.Plugins.Log),
		},
		// Every resource knob is gated on the unified hierarchy actually
		// offering controllers. On a stock WSL 2.4 host it does not, and
		// saying otherwise here is how a user ends up with a silently
		// unlimited container.
		MemoryLimit:        limitsWork,
		SwapLimit:          limitsWork,
		CPUCfsPeriod:       limitsWork,
		CPUCfsQuota:        limitsWork,
		CPUShares:          limitsWork,
		CPUSet:             limitsWork,
		PidsLimit:          limitsWork,
		IPv4Forwarding:     true,
		Debug:              s.opts.Debug,
		NGoroutines:        runtime.NumGoroutine(),
		SystemTime:         time.Now().Format(time.RFC3339Nano),
		LoggingDriver:      info.LoggingDriver,
		CgroupDriver:       info.CgroupDriver,
		CgroupVersion:      info.CgroupVersion,
		NEventsListener:    s.backend.Events().Subscribers(),
		KernelVersion:      info.KernelVersion,
		OperatingSystem:    info.OperatingSystem,
		OSType:             info.OSType,
		Architecture:       info.Architecture,
		NCPU:               info.NCPU,
		MemTotal:           info.MemTotal,
		IndexServerAddress: "https://index.docker.io/v1/",
		RegistryConfig: InfoRegistryConfig{
			AllowNondistributableArtifactsCIDRs:     []string{},
			AllowNondistributableArtifactsHostnames: []string{},
			InsecureRegistryCIDRs:                   []string{"127.0.0.0/8"},
			IndexConfigs: map[string]InfoIndexConfig{
				"docker.io": {Name: "docker.io", Secure: true, Official: true},
			},
			Mirrors: []string{},
		},
		GenericResources:   nil,
		Name:               info.Name,
		Labels:             []string{},
		ServerVersion:      info.ServerVersion,
		Runtimes:           runtimes,
		DefaultRuntime:     info.DefaultRuntime,
		Swarm:              InfoSwarm{LocalNodeState: "inactive"},
		LiveRestoreEnabled: true,
		SecurityOptions:    stringsOrEmpty(info.SecurityOptions),
		Warnings:           stringsOrEmpty(info.Warnings),
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// Event is one entry of the /events stream.
//
// The lowercase status/id/from fields are the pre-1.22 shape and the
// capitalised ones the modern shape. Docker still sends both, and so does
// hull: compose reads Action and Actor, while several older libraries read
// status and id.
type Event struct {
	// Status is the legacy action field.
	Status string `json:"status,omitempty"`
	// ID is the legacy actor id.
	ID string `json:"id,omitempty"`
	// From is the legacy image reference.
	From string `json:"from,omitempty"`
	// Type is container, image, network, volume or daemon.
	Type string `json:"Type"`
	// Action is the verb.
	Action string `json:"Action"`
	// Actor names the object the event is about.
	Actor EventActor `json:"Actor"`
	// Scope is always "local".
	Scope string `json:"scope"`
	// Time and TimeNano stamp the event.
	Time     int64 `json:"time"`
	TimeNano int64 `json:"timeNano"`
}

// EventActor is the object an event is about.
type EventActor struct {
	// ID is the object's identifier.
	ID string `json:"ID"`
	// Attributes carry the name, image and labels clients filter on.
	Attributes map[string]string `json:"Attributes"`
}

// toAPIEvent converts an engine event into the wire shape.
func toAPIEvent(e types.Event) Event {
	out := Event{
		Type:     e.Type,
		Action:   e.Action,
		Actor:    EventActor{ID: e.Actor.ID, Attributes: mapOrEmpty(e.Actor.Attributes)},
		Scope:    orDefault(e.Scope, "local"),
		Time:     e.Time,
		TimeNano: e.TimeNano,
	}
	if e.Type == events.TypeContainer || e.Type == events.TypeImage {
		out.Status = e.Action
		out.ID = e.Actor.ID
		out.From = e.Actor.Attributes["image"]
	}
	return out
}

// getEvents answers GET /events: replay from ?since, then stream live.
//
// The replay is not optional. compose creates a container and then subscribes;
// without the replay it misses the create event it is waiting for and hangs.
func (s *Server) getEvents(w http.ResponseWriter, r *http.Request) error {
	raw, err := parseFilterArgs(r)
	if err != nil {
		return err
	}
	filter, err := events.ParseFilters(raw)
	if err != nil {
		return wrapStatus(http.StatusBadRequest, err, "%s", err.Error())
	}

	sinceStr, _ := lookupQuery(r, "since")
	untilStr, _ := lookupQuery(r, "until")
	since, err := parseTimestamp(sinceStr, time.Time{})
	if err != nil {
		return err
	}
	until, err := parseTimestamp(untilStr, time.Time{})
	if err != nil {
		return err
	}

	ctx := r.Context()
	ch, unsub := s.backend.Events().Subscribe(ctx, filter, since, until)
	defer unsub()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()

	enc := json.NewEncoder(w)
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			if err := enc.Encode(toAPIEvent(ev)); err != nil {
				return nil
			}
			_ = rc.Flush()
		}
	}
}

// getSystemDF answers GET /system/df.
//
// Per-object sizes that would cost a filesystem walk are reported as -1, which
// is Docker's own "not computed" sentinel, rather than as a plausible zero.
func (s *Server) getSystemDF(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	usage := DiskUsage{
		Images:      []*ImageSummary{},
		Containers:  []*ContainerSummary{},
		Volumes:     []*Volume{},
		BuildCache:  []*BuildCache{},
		BuilderSize: 0,
	}

	imgs, err := s.backend.Images(ctx, engine.ImageListOptions{All: true})
	if err != nil {
		return err
	}
	inUse := map[string]int64{}
	ctrs, err := s.backend.List(ctx, engine.ListOptions{All: true})
	if err != nil {
		return err
	}
	now := time.Now()
	for _, c := range ctrs {
		inUse[c.Image]++
		usage.Containers = append(usage.Containers, containerSummary(c, now))
	}
	for _, img := range imgs {
		sum := imageSummary(img)
		sum.Containers = inUse[img.ID]
		sum.SharedSize = 0
		usage.Images = append(usage.Images, sum)
		usage.LayersSize += img.Size
	}

	vols, err := s.backend.VolumeList(ctx, volumeFiltersAll())
	if err != nil {
		return err
	}
	for _, v := range vols {
		av := volumeToAPI(v)
		av.UsageData = &VolumeUsageData{Size: -1, RefCount: -1}
		usage.Volumes = append(usage.Volumes, av)
	}

	writeJSON(w, http.StatusOK, usage)
	return nil
}

// postAuth answers POST /auth: verify registry credentials.
func (s *Server) postAuth(w http.ResponseWriter, r *http.Request) error {
	var cfg AuthConfig
	if err := decodeJSONBody(r, &cfg); err != nil {
		return err
	}
	user, pass, err := cfg.credentials()
	if err != nil {
		return err
	}
	status, err := s.backend.Login(r.Context(), cfg.ServerAddress, user, pass)
	if err != nil {
		return wrapStatus(http.StatusUnauthorized, err, "%s", errorMessage(err))
	}
	writeJSON(w, http.StatusOK, AuthResponse{Status: status})
	return nil
}
