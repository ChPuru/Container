package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

// testClock is a fixed instant so uptimes and toasts are reproducible.
func testClock() func() time.Time {
	now := time.Date(2026, 9, 19, 17, 30, 0, 0, time.UTC)
	return func() time.Time { return now }
}

// sampleContainers is a small population covering the states the list has to
// render differently.
func sampleContainers() []types.Container {
	now := time.Date(2026, 9, 19, 17, 30, 0, 0, time.UTC)
	return []types.Container{
		{
			ID:        strings.Repeat("a", 64),
			Name:      "web",
			ImageRef:  "nginx:1.27",
			State:     types.StateRunning,
			Created:   now.Add(-2 * time.Hour),
			StartedAt: now.Add(-90 * time.Minute),
			NetworkSettings: types.NetworkSettings{
				Ports: map[string][]types.PortBinding{
					"80/tcp": {{HostIP: "0.0.0.0", HostPort: "8080"}},
				},
				Networks: map[string]types.EndpointSettings{
					"hull0": {IPAddress: "10.66.0.2", MacAddress: "5a:69:1b:d6:a6:fd"},
				},
			},
		},
		{
			ID:         strings.Repeat("b", 64),
			Name:       "db",
			ImageRef:   "postgres:16",
			State:      types.StateExited,
			ExitCode:   1,
			Created:    now.Add(-3 * time.Hour),
			FinishedAt: now.Add(-10 * time.Minute),
		},
		{
			ID:        strings.Repeat("c", 64),
			Name:      "cache",
			ImageRef:  "redis:7",
			State:     types.StatePaused,
			Created:   now.Add(-time.Hour),
			StartedAt: now.Add(-time.Hour),
		},
	}
}

// newTestModel returns a model of a known size holding the sample containers.
func newTestModel(t *testing.T, w, h int) *Model {
	t.Helper()
	m := NewModel()
	m.Now = testClock()
	m.SetSize(w, h)
	m.SetContainers(sampleContainers())
	return m
}

func TestModelSortsRunningFirst(t *testing.T) {
	m := newTestModel(t, 120, 40)
	got := make([]string, 0, len(m.Visible()))
	for _, c := range m.Visible() {
		got = append(got, c.Name)
	}
	want := []string{"web", "cache", "db"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestModelFilter(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		want   []string
	}{
		{"empty shows everything", "", []string{"web", "cache", "db"}},
		{"by name", "we", []string{"web"}},
		{"case insensitive", "WEB", []string{"web"}},
		{"by image", "redis", []string{"cache"}},
		{"by state", "exited", []string{"db"}},
		{"by id prefix", strings.Repeat("b", 6), []string{"db"}},
		{"no match", "zzz", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModel(t, 120, 40)
			m.SetFilter(tc.filter)
			var got []string
			for _, c := range m.Visible() {
				got = append(got, c.Name)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("filter %q matched %v, want %v", tc.filter, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("filter %q matched %v, want %v", tc.filter, got, tc.want)
				}
			}
		})
	}
}

func TestModelSelectionSurvivesReordering(t *testing.T) {
	m := newTestModel(t, 120, 40)
	m.Apply(RuneKey('j')) // select "cache"
	if got := m.SelectedID(); got != strings.Repeat("c", 64) {
		t.Fatalf("selected %q, want the second row", ShortID(got))
	}

	// The engine reports the same containers in a different order, and the
	// one that was selected is now last.
	cs := sampleContainers()
	cs[0], cs[2] = cs[2], cs[0]
	m.SetContainers(cs)

	if got := m.SelectedID(); got != strings.Repeat("c", 64) {
		t.Errorf("selection moved to %q after a refresh", ShortID(got))
	}
}

func TestModelSelectionClampsWhenContainersDisappear(t *testing.T) {
	m := newTestModel(t, 120, 40)
	m.Apply(RuneKey('G'))
	if got := m.SelectedID(); got != strings.Repeat("b", 64) {
		t.Fatalf("G did not select the last row, got %q", ShortID(got))
	}
	m.SetContainers(sampleContainers()[:1])
	if _, ok := m.Selected(); !ok {
		t.Fatal("selection lost entirely")
	}
	if got := m.SelectedID(); got != strings.Repeat("a", 64) {
		t.Errorf("selection = %q, want the only remaining container", ShortID(got))
	}

	m.SetContainers(nil)
	if _, ok := m.Selected(); ok {
		t.Error("an empty list must have no selection")
	}
}

func TestModelKeyCommands(t *testing.T) {
	tests := []struct {
		name  string
		keys  []Key
		want  CommandKind
		force bool
	}{
		{"s stops the selection", []Key{RuneKey('s')}, CmdStop, false},
		{"S starts the selection", []Key{RuneKey('S')}, CmdStart, false},
		{"r restarts the selection", []Key{RuneKey('r')}, CmdRestart, false},
		{"p pauses a running container", []Key{RuneKey('p')}, CmdPause, false},
		{"e opens a shell", []Key{RuneKey('e')}, CmdExec, false},
		{"q quits", []Key{RuneKey('q')}, CmdQuit, false},
		{"d then y deletes", []Key{RuneKey('d'), RuneKey('y')}, CmdRemove, true},
		{"d then n does not", []Key{RuneKey('d'), RuneKey('n')}, CmdNone, false},
		{"d then escape does not", []Key{RuneKey('d'), Key{Type: KeyEscape}}, CmdNone, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModel(t, 120, 40)
			var cmd Command
			for _, k := range tc.keys {
				cmd = m.Apply(k)
			}
			if cmd.Kind != tc.want {
				t.Fatalf("command = %v, want %v", cmd.Kind, tc.want)
			}
			if cmd.Force != tc.force {
				t.Errorf("force = %v, want %v", cmd.Force, tc.force)
			}
			if tc.want != CmdNone && tc.want != CmdQuit && cmd.Container.Name != "web" {
				t.Errorf("command carried %q, want the selected container", cmd.Container.Name)
			}
		})
	}
}

func TestModelPauseTogglesOnAPausedContainer(t *testing.T) {
	m := newTestModel(t, 120, 40)
	m.Apply(RuneKey('j')) // "cache" is paused
	cmd := m.Apply(RuneKey('p'))
	if cmd.Kind != CmdUnpause {
		t.Errorf("p on a paused container = %v, want CmdUnpause", cmd.Kind)
	}
}

func TestModelDeleteAsksFirst(t *testing.T) {
	m := newTestModel(t, 120, 40)
	if cmd := m.Apply(RuneKey('d')); cmd.Kind != CmdNone {
		t.Fatalf("d issued %v immediately, it must ask first", cmd.Kind)
	}
	if m.Mode() != ModeConfirm {
		t.Fatalf("mode = %v, want ModeConfirm", m.Mode())
	}
	// While the question is up, the keys that would act elsewhere do not.
	if cmd := m.Apply(RuneKey('s')); cmd.Kind != CmdNone {
		t.Errorf("s during a confirmation issued %v", cmd.Kind)
	}
	if cmd := m.Apply(RuneKey('y')); cmd.Kind != CmdRemove {
		t.Errorf("y = %v, want CmdRemove", cmd.Kind)
	}
	if m.Mode() != ModeNormal {
		t.Errorf("mode = %v after answering, want ModeNormal", m.Mode())
	}
}

func TestModelFilterModeTypesInsteadOfActing(t *testing.T) {
	m := newTestModel(t, 120, 40)
	m.Apply(RuneKey('/'))
	if m.Mode() != ModeFilter {
		t.Fatalf("mode = %v, want ModeFilter", m.Mode())
	}
	for _, r := range "db" {
		if cmd := m.Apply(RuneKey(r)); cmd.Kind != CmdNone {
			t.Fatalf("typing %q issued %v", r, cmd.Kind)
		}
	}
	if m.Filter() != "db" {
		t.Errorf("filter = %q, want %q", m.Filter(), "db")
	}
	if len(m.Visible()) != 1 || m.Visible()[0].Name != "db" {
		t.Errorf("filter did not narrow the list: %d rows", len(m.Visible()))
	}
	m.Apply(Key{Type: KeyBackspace})
	if m.Filter() != "d" {
		t.Errorf("backspace left %q", m.Filter())
	}
	m.Apply(Key{Type: KeyEscape})
	if m.Mode() != ModeNormal {
		t.Errorf("escape did not leave filter mode")
	}
	if m.Filter() != "" {
		t.Errorf("escape left the filter as %q, want the text from before", m.Filter())
	}
	if len(m.Visible()) != 3 {
		t.Errorf("cancelling the filter did not restore the list")
	}
}

func TestModelTabCycling(t *testing.T) {
	m := newTestModel(t, 120, 40)
	want := []DetailTab{TabStats, TabInspect, TabPorts, TabLogs}
	for _, w := range want {
		m.Apply(Key{Type: KeyTab})
		if m.Tab() != w {
			t.Fatalf("tab = %v, want %v", m.Tab(), w)
		}
	}
	m.Apply(Key{Type: KeyBackTab})
	if m.Tab() != TabPorts {
		t.Errorf("shift-tab = %v, want TabPorts", m.Tab())
	}
	m.Apply(RuneKey('3'))
	if m.Tab() != TabInspect {
		t.Errorf("3 = %v, want TabInspect", m.Tab())
	}
	m.Apply(RuneKey('l'))
	if m.Tab() != TabLogs {
		t.Errorf("l = %v, want TabLogs", m.Tab())
	}
}

func TestModelHelpOverlay(t *testing.T) {
	m := newTestModel(t, 120, 40)
	m.Apply(RuneKey('?'))
	if m.Mode() != ModeHelp {
		t.Fatalf("mode = %v, want ModeHelp", m.Mode())
	}
	m.Apply(RuneKey('x'))
	if m.Mode() != ModeNormal {
		t.Errorf("any key should close the help overlay, mode = %v", m.Mode())
	}
}

func TestRing(t *testing.T) {
	r := newRing[int](3)
	if r.len() != 0 {
		t.Fatalf("new ring holds %d", r.len())
	}
	if _, ok := r.last(); ok {
		t.Error("an empty ring has no last value")
	}
	for i := 1; i <= 5; i++ {
		r.add(i)
	}
	got := r.slice()
	want := []int{3, 4, 5}
	if len(got) != len(want) {
		t.Fatalf("ring = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ring = %v, want %v", got, want)
		}
	}
	if v, ok := r.last(); !ok || v != 5 {
		t.Errorf("last = %v, %v; want 5, true", v, ok)
	}
}

func TestModelStatsHistory(t *testing.T) {
	m := newTestModel(t, 120, 40)
	m.StatsHistory = 3
	id := m.SelectedID()
	for i := range 5 {
		m.AddStats(id, types.Stats{
			CPUUsage: uint64(i+1) * 10, PreCPUUsage: uint64(i) * 10,
			SystemUsage: uint64(i+1) * 100, PreSystemUsage: uint64(i) * 100,
			OnlineCPUs: 1, MemoryUsage: 1000, MemoryCache: 200,
		})
	}
	ser := m.series[id]
	if ser == nil {
		t.Fatal("no series recorded")
	}
	if got := ser.cpu.len(); got != 3 {
		t.Errorf("cpu history = %d samples, want 3", got)
	}
	if got, _ := ser.mem.last(); got != 800 {
		t.Errorf("memory sample = %v, want usage minus cache", got)
	}
	if _, ok := m.Stats(id); !ok {
		t.Error("Stats reported nothing after five samples")
	}
	if _, ok := m.Stats("nosuch"); ok {
		t.Error("Stats invented a series")
	}
}

func TestModelWarningsMarkTheRow(t *testing.T) {
	m := newTestModel(t, 120, 40)
	id := m.SelectedID()
	m.SetWarnings(id, []string{"memory limit not applied: no cgroup v2 controllers"})
	m.Refresh()
	if got := m.table.Rows[0].Cells[1]; !strings.HasPrefix(got, "! ") {
		t.Errorf("row name = %q, want a warning marker", got)
	}
	if len(m.Warnings(id)) != 1 {
		t.Errorf("warnings not recorded")
	}
	m.SetWarnings(id, nil)
	if len(m.Warnings(id)) != 0 {
		t.Errorf("warnings not cleared")
	}
}

func TestModelLogRing(t *testing.T) {
	m := newTestModel(t, 120, 40)
	id := m.SelectedID()
	m.AddLog(id, LogLine{Line: "first", Stream: "stdout"})
	m.AddLog(id, LogLine{Line: "second", Stream: "stderr"})
	got := m.Logs(id)
	if len(got) != 2 || got[0].Line != "first" || got[1].Stream != "stderr" {
		t.Fatalf("logs = %+v", got)
	}
	m.ClearLogs(id)
	if len(m.Logs(id)) != 0 {
		t.Error("ClearLogs left lines behind")
	}
}

func TestModelDetailScrollDirection(t *testing.T) {
	m := newTestModel(t, 100, 30)
	id := m.SelectedID()
	for i := range 50 {
		m.AddLog(id, LogLine{Line: "line " + string(rune('a'+i%26))})
	}

	// The logs pane is anchored at the bottom, so page up walks back into
	// the history and page down returns to the newest line.
	m.SetTab(TabLogs)
	if !m.Following() {
		t.Fatal("a fresh logs pane should be following")
	}
	m.Apply(Key{Type: KeyPageUp})
	if m.scroll[TabLogs] <= 0 {
		t.Errorf("page up in the logs pane = %d, want a positive offset back in time", m.scroll[TabLogs])
	}
	if m.Following() {
		t.Error("scrolling back must stop following")
	}
	m.Apply(Key{Type: KeyPageDown})
	if got := m.scroll[TabLogs]; got != 0 {
		t.Errorf("page down did not return to the newest line: %d", got)
	}
	if !m.Following() {
		t.Error("returning to the bottom must resume following")
	}
	// It cannot scroll past the newest line.
	m.Apply(Key{Type: KeyPageDown})
	if got := m.scroll[TabLogs]; got != 0 {
		t.Errorf("scrolled past the end: %d", got)
	}

	// The inspect pane is anchored at the top, so the sign is the other way
	// round.
	m.SetTab(TabInspect)
	m.Apply(Key{Type: KeyPageDown})
	if m.scroll[TabInspect] <= 0 {
		t.Errorf("page down in the inspect pane = %d, want a positive offset", m.scroll[TabInspect])
	}
	m.Apply(Key{Type: KeyPageUp})
	if got := m.scroll[TabInspect]; got != 0 {
		t.Errorf("page up did not return to the top: %d", got)
	}
}

func TestModelSelectionResetsTheDetailScroll(t *testing.T) {
	m := newTestModel(t, 100, 30)
	m.SetTab(TabLogs)
	m.Apply(Key{Type: KeyPageUp})
	if m.scroll[TabLogs] == 0 {
		t.Fatal("test setup did not scroll")
	}
	m.Apply(RuneKey('j'))
	if m.scroll[TabLogs] != 0 {
		t.Errorf("the detail pane belongs to the container, not the pane: offset %d", m.scroll[TabLogs])
	}
}

func TestModelToastExpires(t *testing.T) {
	now := time.Date(2026, 9, 19, 17, 30, 0, 0, time.UTC)
	m := NewModel()
	m.Now = func() time.Time { return now }
	m.Toast("stopped web", m.Theme.Base)
	if got, _ := m.toastText(); got != "stopped web" {
		t.Fatalf("toast = %q", got)
	}
	now = now.Add(10 * time.Second)
	if got, _ := m.toastText(); got != "" {
		t.Errorf("toast = %q after ten seconds, want it expired", got)
	}
}
