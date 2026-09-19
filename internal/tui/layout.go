package tui

// Layout is where every pane lives for one screen size. It is a pure function
// of width and height - [ComputeLayout] - so the whole geometry, including
// every degradation rule, is testable without a terminal.
//
// The dashboard has four panes and a status bar:
//
//	+--------------------------------------------------+
//	| containers  id name image state up cpu mem ports  |
//	+-----------------------------------+--------------+
//	| detail  [Logs|Stats|Inspect|Ports]| events       |
//	|                                   |              |
//	+-----------------------------------+--------------+
//	| status  version  counts  free space  warnings     |
//	+--------------------------------------------------+
//
// The events strip only moves to the right of the detail pane when the
// terminal is at least [WideWidth] columns; below that it is a strip under the
// detail pane, and on a short screen it disappears entirely rather than
// squeezing the detail pane to nothing.
type Layout struct {
	// Width and Height are the screen size this layout was computed for.
	Width, Height int

	// Containers is the container table, including its header row.
	Containers Rect
	// Tabs is the one-row tab bar at the top of the detail pane.
	Tabs Rect
	// Detail is the body of the detail pane, below the tab bar.
	Detail Rect
	// Events is the event strip. It is empty when the screen is too short
	// to carry one.
	Events Rect
	// Status is the one-row status bar at the bottom of the screen.
	Status Rect

	// Narrow reports a terminal below [MinWidth] columns. Widgets drop
	// their lower-priority columns and the chrome thins out.
	Narrow bool
	// Wide reports a terminal at [WideWidth] columns or more, where the
	// event strip becomes a right-hand column.
	Wide bool
	// TooSmall reports a terminal that cannot usefully hold the dashboard
	// at all. The view then draws a single explanatory line, because a
	// layout squeezed below this is noise rather than information.
	TooSmall bool
}

// Screen-size thresholds. They are constants rather than options because they
// describe what fits, not what anyone prefers.
const (
	// MinWidth is the width below which the dashboard is in narrow mode:
	// the classic 80-column terminal is the boundary, not a target.
	MinWidth = 80
	// WideWidth is the width at which the event strip moves beside the
	// detail pane instead of under it.
	WideWidth = 120
	// MinUsableWidth and MinUsableHeight are the smallest screen the
	// dashboard will draw on at all.
	MinUsableWidth  = 24
	MinUsableHeight = 8
)

// eventsColumnWidth returns the width of the right-hand event column on a wide
// screen: a third of the screen, held between 28 and 48 columns so it neither
// starves the detail pane nor wastes an ultra-wide terminal.
func eventsColumnWidth(w int) int {
	return clampInt(w/3, 28, 48)
}

// ComputeLayout tiles a screen of w by h cells into panes.
//
// Every returned rectangle is inside the screen, no two overlap, and together
// they cover it, at every size from [MinUsableWidth] upward. Below that,
// TooSmall is set and only Status carries a rectangle.
func ComputeLayout(w, h int) Layout {
	lay := Layout{
		Width:  w,
		Height: h,
		Narrow: w < MinWidth,
		Wide:   w >= WideWidth,
	}
	if w < MinUsableWidth || h < MinUsableHeight {
		lay.TooSmall = true
		lay.Wide = false
		if w > 0 && h > 0 {
			lay.Status = Rect{X: 0, Y: h - 1, W: w, H: 1}
		}
		return lay
	}

	lay.Status = Rect{X: 0, Y: h - 1, W: w, H: 1}
	body := h - 1

	// The container table gets two fifths of the body, but never fewer
	// than three rows (header plus two containers) and never so many that
	// the detail pane loses its tab bar and two lines.
	ctrH := clampInt(body*2/5, 3, body-3)
	lay.Containers = Rect{X: 0, Y: 0, W: w, H: ctrH}

	bandY := ctrH
	bandH := body - ctrH

	var detailBand, eventsBand Rect
	switch {
	case lay.Wide:
		ew := eventsColumnWidth(w)
		detailBand = Rect{X: 0, Y: bandY, W: w - ew, H: bandH}
		eventsBand = Rect{X: w - ew, Y: bandY, W: ew, H: bandH}
	default:
		evH := 0
		switch {
		case bandH >= 12:
			evH = 6
		case bandH >= 9:
			evH = 4
		case bandH >= 7:
			evH = 3
		}
		detailBand = Rect{X: 0, Y: bandY, W: w, H: bandH - evH}
		eventsBand = Rect{X: 0, Y: bandY + bandH - evH, W: w, H: evH}
	}

	lay.Events = eventsBand
	// The first row of the detail band is the tab bar; the rest is body.
	lay.Tabs = Rect{X: detailBand.X, Y: detailBand.Y, W: detailBand.W, H: 1}
	lay.Detail = Rect{
		X: detailBand.X,
		Y: detailBand.Y + 1,
		W: detailBand.W,
		H: detailBand.H - 1,
	}
	if lay.Detail.H < 0 {
		lay.Detail.H = 0
	}
	return lay
}

// clampInt returns v held between lo and hi. When hi is below lo the lower
// bound wins, which is what a pane that no longer fits should do.
func clampInt(v, lo, hi int) int {
	if hi < lo {
		return lo
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
