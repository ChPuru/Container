package events

import "github.com/ChPuru/hull/internal/types"

// Event scopes. hull is a single-node engine, so every event is local.
const (
	// ScopeLocal is the scope stamped on every hull event.
	ScopeLocal = "local"
)

// Event types, matching the Docker Engine API vocabulary.
const (
	// TypeContainer marks events about a container.
	TypeContainer = "container"
	// TypeImage marks events about an image.
	TypeImage = "image"
	// TypeNetwork marks events about a network.
	TypeNetwork = "network"
	// TypeVolume marks events about a volume.
	TypeVolume = "volume"
	// TypeDaemon marks events about the engine itself.
	TypeDaemon = "daemon"
)

// Container actions, the full set Docker emits.
const (
	// ActionCreate is emitted when a container is created.
	ActionCreate = "create"
	// ActionStart is emitted when a container's init process is running.
	ActionStart = "start"
	// ActionRestart is emitted when a container is restarted.
	ActionRestart = "restart"
	// ActionStop is emitted when a stop was requested and completed.
	ActionStop = "stop"
	// ActionDie is emitted when the init process exits; carries exitCode.
	ActionDie = "die"
	// ActionKill is emitted when a signal is delivered; carries signal.
	ActionKill = "kill"
	// ActionOOM is emitted when the kernel OOM-kills the container.
	ActionOOM = "oom"
	// ActionPause is emitted when the cgroup is frozen.
	ActionPause = "pause"
	// ActionUnpause is emitted when the cgroup is thawed.
	ActionUnpause = "unpause"
	// ActionDestroy is emitted when a container, network or volume is removed.
	ActionDestroy = "destroy"
	// ActionRename is emitted on rename; carries oldName.
	ActionRename = "rename"
	// ActionUpdate is emitted when resources are updated in place.
	ActionUpdate = "update"
	// ActionAttach is emitted when a client attaches to the container's io.
	ActionAttach = "attach"
	// ActionCommit is emitted when a container is committed to an image.
	ActionCommit = "commit"
	// ActionCopy is emitted on an archive copy in or out of a container.
	ActionCopy = "copy"
	// ActionExecCreate is emitted when an exec is created; Docker appends
	// ": <cmd>" to this action.
	ActionExecCreate = "exec_create"
	// ActionExecStart is emitted when an exec starts; Docker appends
	// ": <cmd>" to this action.
	ActionExecStart = "exec_start"
	// ActionExecDie is emitted when an exec process exits; carries exitCode.
	ActionExecDie = "exec_die"
	// ActionExport is emitted when a container filesystem is exported.
	ActionExport = "export"
	// ActionHealthStatus is emitted on a healthcheck transition; Docker
	// appends ": healthy" or ": unhealthy".
	ActionHealthStatus = "health_status"
	// ActionResize is emitted when a tty is resized; carries height/width.
	ActionResize = "resize"
	// ActionTop is emitted when the process list is inspected.
	ActionTop = "top"
	// ActionPrune is emitted when a prune sweep completes.
	ActionPrune = "prune"
)

// Actions emitted for images, networks, volumes and the daemon that are not
// part of the container set above.
const (
	// ActionPull is emitted when an image is pulled.
	ActionPull = "pull"
	// ActionPush is emitted when an image is pushed.
	ActionPush = "push"
	// ActionTag is emitted when a tag is added to an image.
	ActionTag = "tag"
	// ActionUntag is emitted when a tag is removed from an image.
	ActionUntag = "untag"
	// ActionDelete is emitted when an image is deleted.
	ActionDelete = "delete"
	// ActionImport is emitted when an image is imported from a tarball.
	ActionImport = "import"
	// ActionLoad is emitted when an image archive is loaded.
	ActionLoad = "load"
	// ActionSave is emitted when an image archive is saved.
	ActionSave = "save"
	// ActionConnect is emitted when a container joins a network.
	ActionConnect = "connect"
	// ActionDisconnect is emitted when a container leaves a network.
	ActionDisconnect = "disconnect"
	// ActionRemove is emitted when a network or volume is removed.
	ActionRemove = "remove"
	// ActionMount is emitted when a volume is mounted into a container.
	ActionMount = "mount"
	// ActionUnmount is emitted when a volume is unmounted.
	ActionUnmount = "unmount"
	// ActionReload is emitted when the daemon reloads its configuration.
	ActionReload = "reload"
)

// ContainerActions is the full set of container actions hull emits, in the
// order Docker documents them. Useful for CLI completion and validation.
var ContainerActions = []string{
	ActionCreate, ActionStart, ActionRestart, ActionStop, ActionDie,
	ActionKill, ActionOOM, ActionPause, ActionUnpause, ActionDestroy,
	ActionRename, ActionUpdate, ActionAttach, ActionCommit, ActionCopy,
	ActionExecCreate, ActionExecStart, ActionExecDie, ActionExport,
	ActionHealthStatus, ActionResize, ActionTop, ActionPrune,
}

// Container builds a container event for c.
//
// The attributes carry "image", "name" and every container label, because
// that is exactly what Docker emits and what docker compose relies on to
// track project/service membership. Entries in extra are applied last and
// therefore win; pass things like {"exitCode": "137"} there. Both c and extra
// may be nil, and neither is retained: the maps are copied.
func Container(action string, c *types.Container, extra map[string]string) types.Event {
	attrs := make(map[string]string, len(extra)+4)
	e := types.Event{Type: TypeContainer, Action: action, Scope: ScopeLocal}

	if c != nil {
		e.Actor.ID = c.ID
		for k, v := range c.Config.Labels {
			attrs[k] = v
		}
		img := c.ImageRef
		if img == "" {
			img = c.Image
		}
		if img != "" {
			attrs["image"] = img
		}
		if c.Name != "" {
			attrs["name"] = c.Name
		}
	}
	for k, v := range extra {
		attrs[k] = v
	}
	e.Actor.Attributes = attrs
	return e
}

// Image builds an image event. id is the image ID or reference the action
// applies to; the first tag, when present, becomes the "name" attribute as
// Docker does, and every tag is reported in "tags" as a comma-separated list.
func Image(action, id string, tags []string) types.Event {
	attrs := make(map[string]string, 2)
	name := id
	if len(tags) > 0 && tags[0] != "" {
		name = tags[0]
		attrs["tags"] = joinNonEmpty(tags, ",")
	}
	attrs["name"] = name
	return types.Event{
		Type:   TypeImage,
		Action: action,
		Scope:  ScopeLocal,
		Actor:  types.EventActor{ID: id, Attributes: attrs},
	}
}

// Network builds a network event. When containerID is non-empty it is
// reported in the "container" attribute, which is what connect/disconnect
// events carry. n may be nil.
func Network(action string, n *types.Network, containerID string) types.Event {
	attrs := make(map[string]string, 4)
	e := types.Event{Type: TypeNetwork, Action: action, Scope: ScopeLocal}
	if n != nil {
		e.Actor.ID = n.ID
		for k, v := range n.Labels {
			attrs[k] = v
		}
		if n.Name != "" {
			attrs["name"] = n.Name
		}
		if n.Driver != "" {
			attrs["type"] = n.Driver
		}
	}
	if containerID != "" {
		attrs["container"] = containerID
	}
	e.Actor.Attributes = attrs
	return e
}

// Volume builds a volume event. A volume's name is its id, and its labels
// become the event attributes so label filters work on volume events too.
// labels may be nil and is copied, not retained.
func Volume(action, name string, labels map[string]string) types.Event {
	attrs := make(map[string]string, len(labels))
	for k, v := range labels {
		attrs[k] = v
	}
	return types.Event{
		Type:   TypeVolume,
		Action: action,
		Scope:  ScopeLocal,
		Actor:  types.EventActor{ID: name, Attributes: attrs},
	}
}

// Daemon builds an engine-level event. When attrs carries an "id" entry it is
// also used as the actor id, matching Docker's daemon events. attrs may be
// nil and is copied, not retained.
func Daemon(action string, attrs map[string]string) types.Event {
	cp := make(map[string]string, len(attrs))
	for k, v := range attrs {
		cp[k] = v
	}
	return types.Event{
		Type:   TypeDaemon,
		Action: action,
		Scope:  ScopeLocal,
		Actor:  types.EventActor{ID: cp["id"], Attributes: cp},
	}
}

func joinNonEmpty(vals []string, sep string) string {
	out := ""
	for _, v := range vals {
		if v == "" {
			continue
		}
		if out != "" {
			out += sep
		}
		out += v
	}
	return out
}
