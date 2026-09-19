package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

// frame renders the model at a size and returns the screen as text.
func frame(m *Model, w, h int) string {
	m.SetSize(w, h)
	b := NewBuffer(w, h)
	m.Refresh()
	m.Render(b)
	return b.String()
}

// wideEnough reports whether every line of a frame fits the width, which is
// the property that stops a pane spilling into its neighbour.
func wideEnough(t *testing.T, screen string, w int) {
	t.Helper()
	for i, line := range strings.Split(screen, "\n") {
		if n := len([]rune(line)); n > w {
			t.Fatalf("line %d is %d cells wide, screen is %d: %q", i, n, w, line)
		}
	}
}

func TestViewRendersAtEverySize(t *testing.T) {
	sizes := []struct {
		name string
		w, h int
	}{
		{"40 columns", 40, 20},
		{"80 columns", 80, 24},
		{"120 columns", 120, 40},
		{"tiny", 20, 6},
	}
	for _, tc := range sizes {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModel(t, tc.w, tc.h)
			m.SetInfo(Info{
				Version:           "0.1.0-dev",
				DataRoot:          "/var/lib/hull",
				ContainersRunning: 1,
				ContainersPaused:  1,
				ContainersStopped: 1,
				Runtime:           "crun",
				OCIVersion:        "1.1.0",
				CgroupVersion:     "hybrid",
				Warnings:          []string{"no delegated cgroup v2 controllers"},
			})
			m.SetDiskUsage(DiskUsage{Path: "/var/lib/hull", Free: 12 << 30, Total: 100 << 30})
			screen := frame(m, tc.w, tc.h)
			wideEnough(t, screen, tc.w)
			if lines := strings.Split(screen, "\n"); len(lines) != tc.h {
				t.Fatalf("frame has %d lines, want %d", len(lines), tc.h)
			}
			if tc.w >= MinUsableWidth && tc.h >= MinUsableHeight {
				if !strings.Contains(screen, "web") {
					t.Errorf("container list missing from the frame:\n%s", screen)
				}
				if !strings.Contains(screen, "hull 0.1.0-dev") {
					t.Errorf("status bar missing from the frame:\n%s", screen)
				}
			} else if !strings.Contains(screen, "too small") {
				t.Errorf("an unusable terminal should say so:\n%s", screen)
			}
		})
	}
}

func TestViewNarrowDropsColumns(t *testing.T) {
	m := newTestModel(t, 40, 20)
	narrow := frame(m, 40, 20)
	wide := frame(m, 160, 40)

	if strings.Contains(narrow, "8080") {
		t.Errorf("the ports column should be dropped at 40 columns:\n%s", narrow)
	}
	if !strings.Contains(wide, "8080") {
		t.Errorf("the ports column should be present at 160 columns:\n%s", wide)
	}
	if !strings.Contains(narrow, "web") {
		t.Errorf("the name column must never be dropped:\n%s", narrow)
	}
}

func TestViewStatusBarCarriesWarnings(t *testing.T) {
	m := newTestModel(t, 120, 40)
	m.SetInfo(Info{
		Version:  "0.1.0-dev",
		Warnings: []string{"cgroup v2 has no delegated controllers", "docker desktop is running"},
	})
	screen := frame(m, 120, 40)
	if !strings.Contains(screen, "2 warnings") {
		t.Errorf("status bar does not report the host warnings:\n%s", screen)
	}
}

func TestViewWarningOverlayShowsTheText(t *testing.T) {
	m := newTestModel(t, 100, 30)
	m.SetInfo(Info{Warnings: []string{"cgroup v2 has no delegated controllers; run wsl --update"}})
	m.Apply(RuneKey('w'))
	screen := frame(m, 100, 30)
	if !strings.Contains(screen, "wsl --update") {
		t.Errorf("warning overlay does not carry the remedy:\n%s", screen)
	}
}

func TestViewInspectTabShowsContainerWarnings(t *testing.T) {
	m := newTestModel(t, 120, 40)
	id := m.SelectedID()
	m.SetWarnings(id, []string{"memory limit not applied: no cgroup v2 controllers delegated"})
	sel, _ := m.Selected()
	m.SetInspect(id, sel)
	m.SetTab(TabInspect)
	screen := frame(m, 120, 40)
	if !strings.Contains(screen, "memory limit not applied") {
		t.Errorf("the engine warning must reach the detail pane:\n%s", screen)
	}
}

func TestViewLogsTab(t *testing.T) {
	m := newTestModel(t, 100, 30)
	id := m.SelectedID()
	m.SetTab(TabLogs)
	if screen := frame(m, 100, 30); !strings.Contains(screen, "waiting for log output") {
		t.Errorf("empty log pane should say it is waiting:\n%s", screen)
	}
	ts := time.Date(2026, 9, 19, 17, 30, 0, 0, time.UTC)
	for i := range 3 {
		m.AddLog(id, LogLine{Time: ts, Stream: "stdout", Line: "line " + string(rune('a'+i))})
	}
	screen := frame(m, 100, 30)
	if !strings.Contains(screen, "line c") {
		t.Errorf("newest log line missing:\n%s", screen)
	}
	if !strings.Contains(screen, "17:30:00") {
		t.Errorf("log timestamp missing:\n%s", screen)
	}
}

func TestViewStatsTab(t *testing.T) {
	m := newTestModel(t, 120, 40)
	id := m.SelectedID()
	m.SetTab(TabStats)
	if screen := frame(m, 120, 40); !strings.Contains(screen, "no stats yet") {
		t.Errorf("a container with no samples should say so:\n%s", screen)
	}
	m.AddStats(id, types.Stats{
		Read:     time.Date(2026, 9, 19, 17, 30, 0, 0, time.UTC),
		CPUUsage: 200, PreCPUUsage: 100,
		SystemUsage: 1000, PreSystemUsage: 0,
		OnlineCPUs:  4,
		MemoryUsage: 300 << 20, MemoryCache: 100 << 20,
		PidsCurrent: 7,
	})
	screen := frame(m, 120, 40)
	if !strings.Contains(screen, "cpu") || !strings.Contains(screen, "mem") {
		t.Errorf("stats tab missing its series:\n%s", screen)
	}
	if !strings.Contains(screen, "unlimited") {
		t.Errorf("an unenforced memory limit must be visible:\n%s", screen)
	}
	if !strings.Contains(screen, "not enforced") {
		t.Errorf("the stats tab must explain an absent limit:\n%s", screen)
	}
}

func TestViewPortsTab(t *testing.T) {
	m := newTestModel(t, 120, 40)
	m.SetTab(TabPorts)
	screen := frame(m, 120, 40)
	if !strings.Contains(screen, "0.0.0.0:8080->80/tcp") {
		t.Errorf("published port missing:\n%s", screen)
	}
	if !strings.Contains(screen, "10.66.0.2") {
		t.Errorf("container address missing:\n%s", screen)
	}
}

func TestViewEventStrip(t *testing.T) {
	m := newTestModel(t, 120, 40)
	m.AddEvent(types.Event{
		Type: "container", Action: "start",
		Actor: types.EventActor{ID: strings.Repeat("a", 64), Attributes: map[string]string{"name": "web"}},
		Time:  time.Date(2026, 9, 19, 17, 29, 0, 0, time.UTC).Unix(),
	})
	screen := frame(m, 120, 40)
	if !strings.Contains(screen, "container start web") {
		t.Errorf("event strip missing the event:\n%s", screen)
	}
}

func TestViewFilterPromptTakesTheStatusBar(t *testing.T) {
	m := newTestModel(t, 100, 30)
	m.Apply(RuneKey('/'))
	m.Apply(RuneKey('w'))
	screen := frame(m, 100, 30)
	lines := strings.Split(screen, "\n")
	if !strings.HasPrefix(lines[len(lines)-1], "/w") {
		t.Errorf("filter prompt missing from the status bar: %q", lines[len(lines)-1])
	}
}

func TestViewEmptyEngine(t *testing.T) {
	m := NewModel()
	m.Now = testClock()
	m.SetSize(80, 24)
	screen := frame(m, 80, 24)
	if !strings.Contains(screen, "no containers") {
		t.Errorf("an empty engine should say so:\n%s", screen)
	}
	if !strings.Contains(screen, "nothing selected") {
		t.Errorf("the detail pane should say nothing is selected:\n%s", screen)
	}
}

func TestViewConfirmOverlay(t *testing.T) {
	m := newTestModel(t, 100, 30)
	m.Apply(RuneKey('d'))
	screen := frame(m, 100, 30)
	if !strings.Contains(screen, "delete web") {
		t.Errorf("confirmation does not name the container:\n%s", screen)
	}
	if !strings.Contains(screen, "cannot be undone") {
		t.Errorf("confirmation does not warn:\n%s", screen)
	}
}

func TestViewHelpOverlayListsEveryKey(t *testing.T) {
	m := newTestModel(t, 100, 30)
	m.Apply(RuneKey('?'))
	screen := frame(m, 100, 30)
	for _, want := range []string{"stop / start", "filter", "quit", "open a shell"} {
		if !strings.Contains(screen, want) {
			t.Errorf("help overlay is missing %q:\n%s", want, screen)
		}
	}
}
