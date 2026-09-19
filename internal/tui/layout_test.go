package tui

import "testing"

// tile checks that a layout covers every cell of the screen exactly once. A
// pane that overlaps another paints over it, and a gap leaves stale cells that
// the diff renderer will never repaint, so this is the invariant that matters.
func tile(t *testing.T, lay Layout, w, h int) {
	t.Helper()
	cover := make([][]int, h)
	for y := range cover {
		cover[y] = make([]int, w)
	}
	rects := map[string]Rect{
		"containers": lay.Containers,
		"tabs":       lay.Tabs,
		"detail":     lay.Detail,
		"events":     lay.Events,
		"status":     lay.Status,
	}
	for name, r := range rects {
		if r.Empty() {
			continue
		}
		if r.X < 0 || r.Y < 0 || r.Right() > w || r.Bottom() > h {
			t.Fatalf("%s rect %+v falls outside the %dx%d screen", name, r, w, h)
		}
		for y := r.Y; y < r.Bottom(); y++ {
			for x := r.X; x < r.Right(); x++ {
				cover[y][x]++
			}
		}
	}
	for y := range cover {
		for x, n := range cover[y] {
			if n != 1 {
				t.Fatalf("cell (%d,%d) covered %d times at %dx%d: %+v", x, y, n, w, h, lay)
			}
		}
	}
}

func TestComputeLayout(t *testing.T) {
	tests := []struct {
		name       string
		w, h       int
		wantNarrow bool
		wantWide   bool
		wantEvents bool
		// eventsRight is true when the event strip is a right-hand column
		// rather than a strip under the detail pane.
		eventsRight bool
	}{
		{name: "40 columns is narrow", w: 40, h: 24, wantNarrow: true, wantEvents: true},
		{name: "80 columns is the boundary", w: 80, h: 24, wantEvents: true},
		{name: "120 columns is wide", w: 120, h: 40, wantWide: true, wantEvents: true, eventsRight: true},
		{name: "200 columns is still wide", w: 200, h: 50, wantWide: true, wantEvents: true, eventsRight: true},
		{name: "a short screen drops the event strip", w: 100, h: 10, wantEvents: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lay := ComputeLayout(tc.w, tc.h)
			if lay.TooSmall {
				t.Fatalf("layout at %dx%d reported too small", tc.w, tc.h)
			}
			if lay.Narrow != tc.wantNarrow {
				t.Errorf("Narrow = %v, want %v", lay.Narrow, tc.wantNarrow)
			}
			if lay.Wide != tc.wantWide {
				t.Errorf("Wide = %v, want %v", lay.Wide, tc.wantWide)
			}
			if got := !lay.Events.Empty(); got != tc.wantEvents {
				t.Errorf("events pane present = %v, want %v (%+v)", got, tc.wantEvents, lay.Events)
			}
			if tc.wantEvents && tc.eventsRight {
				if lay.Events.X == 0 {
					t.Errorf("on a wide screen the events pane should be a right column, got %+v", lay.Events)
				}
				if lay.Events.Y != lay.Tabs.Y {
					t.Errorf("events column should share the detail band: %+v vs %+v", lay.Events, lay.Tabs)
				}
			}
			if tc.wantEvents && !tc.eventsRight && lay.Events.X != 0 {
				t.Errorf("on a narrow screen the events strip spans the width, got %+v", lay.Events)
			}
			if lay.Status.Y != tc.h-1 || lay.Status.H != 1 || lay.Status.W != tc.w {
				t.Errorf("status bar = %+v, want the bottom row", lay.Status)
			}
			if lay.Tabs.H != 1 {
				t.Errorf("tab bar = %+v, want one row", lay.Tabs)
			}
			if lay.Containers.H < 3 {
				t.Errorf("container pane = %+v, want at least a title, a header and a row", lay.Containers)
			}
			if lay.Detail.Y != lay.Tabs.Y+1 {
				t.Errorf("detail body must sit under its tab bar: %+v, %+v", lay.Detail, lay.Tabs)
			}
			tile(t, lay, tc.w, tc.h)
		})
	}
}

func TestComputeLayoutTooSmall(t *testing.T) {
	tests := []struct {
		name string
		w, h int
	}{
		{"no columns", 0, 0},
		{"one column", 1, 24},
		{"too few rows", 100, 4},
		{"just under the floor", MinUsableWidth - 1, MinUsableHeight},
		{"negative", -5, -5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lay := ComputeLayout(tc.w, tc.h)
			if !lay.TooSmall {
				t.Errorf("layout at %dx%d should report too small", tc.w, tc.h)
			}
		})
	}
}

func TestComputeLayoutTilesEverySize(t *testing.T) {
	// Sweep the sizes a real terminal reaches, including the awkward ones
	// either side of every threshold.
	for w := MinUsableWidth; w <= 200; w += 7 {
		for h := MinUsableHeight; h <= 60; h += 3 {
			lay := ComputeLayout(w, h)
			if lay.TooSmall {
				t.Fatalf("%dx%d reported too small", w, h)
			}
			tile(t, lay, w, h)
		}
	}
}

func TestEventsColumnWidth(t *testing.T) {
	tests := []struct {
		w    int
		want int
	}{
		{120, 40},
		{200, 48},
		{84, 28},
	}
	for _, tc := range tests {
		if got := eventsColumnWidth(tc.w); got != tc.want {
			t.Errorf("eventsColumnWidth(%d) = %d, want %d", tc.w, got, tc.want)
		}
	}
}

func TestClampInt(t *testing.T) {
	tests := []struct {
		name      string
		v, lo, hi int
		want      int
	}{
		{"inside", 5, 0, 10, 5},
		{"below", -1, 0, 10, 0},
		{"above", 99, 0, 10, 10},
		{"inverted bounds take the floor", 5, 8, 3, 8},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampInt(tc.v, tc.lo, tc.hi); got != tc.want {
				t.Errorf("clampInt(%d,%d,%d) = %d, want %d", tc.v, tc.lo, tc.hi, got, tc.want)
			}
		})
	}
}
