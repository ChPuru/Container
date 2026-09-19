package events

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rahuldhali/hull/internal/types"
)

// minIDPrefix is the shortest id prefix a container/image/network/volume
// filter may use. Docker accepts any prefix; hull requires three characters so
// a one-letter typo cannot silently subscribe to half the engine.
const minIDPrefix = 3

// Filter selects a subset of the event stream.
//
// Semantics match Docker: different filter KEYS are ANDed, and multiple values
// of the SAME key are ORed. Label filters are the one exception Docker itself
// makes: every label filter must match (they are ANDed with each other), since
// that is what "give me events for containers carrying these labels" means.
//
// The zero Filter matches every event.
type Filter struct {
	// Types matches Event.Type: container, image, network, volume, daemon.
	Types []string
	// Actions matches Event.Action. A value without a colon also matches the
	// compound actions Docker emits, such as "exec_create: /bin/sh".
	Actions []string
	// Containers matches container events by exact id, by an id prefix of at
	// least minIDPrefix characters, or by the "name" attribute.
	Containers []string
	// Images matches image events the same way, plus the image reference.
	Images []string
	// Networks matches network events the same way.
	Networks []string
	// Volumes matches volume events the same way.
	Volumes []string
	// Labels are label keys that must be present on the actor.
	Labels []string
	// LabelPairs are label key/value pairs that must match exactly.
	LabelPairs map[string]string
	// Scopes matches Event.Scope ("local"); hull never emits "swarm".
	Scopes []string
	// Daemons matches daemon events by id or "name" attribute.
	Daemons []string
}

// IsEmpty reports whether the filter constrains nothing and therefore matches
// every event.
func (f Filter) IsEmpty() bool {
	return len(f.Types) == 0 && len(f.Actions) == 0 && len(f.Containers) == 0 &&
		len(f.Images) == 0 && len(f.Networks) == 0 && len(f.Volumes) == 0 &&
		len(f.Labels) == 0 && len(f.LabelPairs) == 0 && len(f.Scopes) == 0 &&
		len(f.Daemons) == 0
}

// Match reports whether e satisfies the filter.
func (f Filter) Match(e types.Event) bool {
	if !matchExact(f.Types, e.Type) {
		return false
	}
	if !matchExact(f.Scopes, e.Scope) {
		return false
	}
	if !matchAction(f.Actions, e.Action) {
		return false
	}
	if !matchActor(f.Containers, e, TypeContainer) {
		return false
	}
	if !matchActor(f.Images, e, TypeImage) {
		return false
	}
	if !matchActor(f.Networks, e, TypeNetwork) {
		return false
	}
	if !matchActor(f.Volumes, e, TypeVolume) {
		return false
	}
	if !matchActor(f.Daemons, e, TypeDaemon) {
		return false
	}
	return f.matchLabels(e.Actor.Attributes)
}

// matchExact is an OR over values, and vacuously true when no value is set.
func matchExact(values []string, got string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		if v == got {
			return true
		}
	}
	return false
}

// matchAction ORs over action names. A filter value with no colon also matches
// the compound forms Docker emits for exec_create, exec_start and
// health_status, e.g. filter "exec_create" matches "exec_create: /bin/sh".
func matchAction(values []string, got string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		if v == got {
			return true
		}
		if !strings.Contains(v, ":") && strings.HasPrefix(got, v+":") {
			return true
		}
	}
	return false
}

// matchActor applies an id/name filter that only constrains events of the
// given type. An event of another type never matches, mirroring Docker.
func matchActor(values []string, e types.Event, want string) bool {
	if len(values) == 0 {
		return true
	}
	if e.Type != want {
		return false
	}
	name := e.Actor.Attributes["name"]
	for _, v := range values {
		if v == "" {
			continue
		}
		if v == e.Actor.ID || v == name {
			return true
		}
		if len(v) >= minIDPrefix && strings.HasPrefix(e.Actor.ID, v) {
			return true
		}
	}
	return false
}

// matchLabels requires every label constraint to hold, as Docker's
// MatchKVList does.
func (f Filter) matchLabels(attrs map[string]string) bool {
	for _, k := range f.Labels {
		if _, ok := attrs[k]; !ok {
			return false
		}
	}
	for k, want := range f.LabelPairs {
		got, ok := attrs[k]
		if !ok || got != want {
			return false
		}
	}
	return true
}

// InvalidFilterError is returned by ParseFilters for a filter key hull does
// not understand. Its message is deliberately shaped like Docker's so the
// stock CLI prints something familiar; the API layer should map it to HTTP
// 400.
type InvalidFilterError struct {
	// Key is the offending filter name.
	Key string
	// Reason, when non-empty, explains why a key Docker accepts is refused.
	Reason string
}

// Error implements error.
func (e *InvalidFilterError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("Invalid filter '%s': %s", e.Key, e.Reason)
	}
	return fmt.Sprintf("Invalid filter '%s'", e.Key)
}

// swarmOnlyFilters are keys the Docker API defines but that cannot ever match
// on a single-node engine. They are rejected loudly rather than ignored.
var swarmOnlyFilters = map[string]string{
	"config":  "hull is not a swarm manager",
	"node":    "hull is not a swarm manager",
	"plugin":  "hull does not support engine plugins",
	"secret":  "hull is not a swarm manager",
	"service": "hull is not a swarm manager",
}

// ParseFilters builds a Filter from the Docker API's decoded filters JSON, the
// map[string][]string produced by the /events "filters" query parameter.
//
// Recognised keys: type, event, action, container, image, network, volume,
// label, scope, daemon. Any other key yields an *InvalidFilterError.
func ParseFilters(m map[string][]string) (Filter, error) {
	var f Filter
	if len(m) == 0 {
		return f, nil
	}

	// Iterate in a stable order so the reported error is deterministic when
	// more than one key is bad.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		values := m[k]
		switch k {
		case "type":
			f.Types = append(f.Types, values...)
		case "event", "action":
			f.Actions = append(f.Actions, values...)
		case "container":
			f.Containers = append(f.Containers, values...)
		case "image":
			f.Images = append(f.Images, values...)
		case "network":
			f.Networks = append(f.Networks, values...)
		case "volume":
			f.Volumes = append(f.Volumes, values...)
		case "scope":
			f.Scopes = append(f.Scopes, values...)
		case "daemon":
			f.Daemons = append(f.Daemons, values...)
		case "label":
			for _, v := range values {
				key, val, hasVal := strings.Cut(v, "=")
				if key == "" {
					return Filter{}, &InvalidFilterError{Key: "label", Reason: "empty label key"}
				}
				if hasVal {
					if f.LabelPairs == nil {
						f.LabelPairs = make(map[string]string)
					}
					f.LabelPairs[key] = val
					continue
				}
				f.Labels = append(f.Labels, key)
			}
		default:
			if reason, ok := swarmOnlyFilters[k]; ok {
				return Filter{}, &InvalidFilterError{Key: k, Reason: reason}
			}
			return Filter{}, &InvalidFilterError{Key: k}
		}
	}
	return f, nil
}
