package tui

import "github.com/rahuldhali/hull/internal/types"

// Theme is every style the dashboard draws with, in one place, so a
// monochrome terminal is one substitution rather than a hundred conditionals.
type Theme struct {
	// Base is the ordinary text style.
	Base Style
	// Dim is for data the engine could not supply, and for chrome.
	Dim Style
	// PaneTitle and Rule draw a pane heading and its rule.
	PaneTitle Style
	Rule      Style
	// TableHeader, TableRow and TableSelected paint the container list.
	TableHeader   Style
	TableRow      Style
	TableSelected Style
	// Running, Paused, Exited and Unhealthy colour a container by state.
	Running   Style
	Paused    Style
	Exited    Style
	Unhealthy Style
	// TabActive and TabInactive paint the detail tab bar.
	TabActive   Style
	TabInactive Style
	// Spark paints the sparklines.
	Spark Style
	// Event paints the event strip, and EventAction its action word.
	Event       Style
	EventAction Style
	// Status paints the status bar, StatusKey its labels, and StatusWarn
	// the warning count.
	Status     Style
	StatusKey  Style
	StatusWarn Style
	// Warn and Error carry warnings and failures.
	Warn  Style
	Error Style
	// Prompt paints the filter prompt.
	Prompt Style
	// OverlayText, OverlayBorder and OverlayTitle paint an overlay.
	OverlayText   Style
	OverlayBorder Style
	OverlayTitle  Style
	// JSONKey and JSONValue paint the inspect tab.
	JSONKey   Style
	JSONValue Style
}

// DefaultTheme is the colour scheme hull ships. It uses the sixteen ANSI
// colours only, so it inherits whatever palette the user has configured
// instead of fighting it.
func DefaultTheme() Theme {
	return Theme{
		Base:          Style{},
		Dim:           Style{Attrs: AttrDim},
		PaneTitle:     Style{Fg: ColorBrightCyan, Attrs: AttrBold},
		Rule:          Style{Fg: ColorBrightBlack},
		TableHeader:   Style{Fg: ColorBrightBlack, Attrs: AttrBold},
		TableRow:      Style{},
		TableSelected: Style{Attrs: AttrReverse | AttrBold},
		Running:       Style{Fg: ColorGreen},
		Paused:        Style{Fg: ColorYellow},
		Exited:        Style{Fg: ColorBrightBlack},
		Unhealthy:     Style{Fg: ColorRed, Attrs: AttrBold},
		TabActive:     Style{Attrs: AttrReverse},
		TabInactive:   Style{Fg: ColorBrightBlack},
		Spark:         Style{Fg: ColorCyan},
		Event:         Style{},
		EventAction:   Style{Fg: ColorBrightBlue},
		Status:        Style{Attrs: AttrReverse},
		StatusKey:     Style{Attrs: AttrReverse | AttrBold},
		StatusWarn:    Style{Fg: ColorYellow, Attrs: AttrReverse | AttrBold},
		Warn:          Style{Fg: ColorYellow},
		Error:         Style{Fg: ColorRed, Attrs: AttrBold},
		Prompt:        Style{Fg: ColorBrightYellow, Attrs: AttrBold},
		OverlayText:   Style{},
		OverlayBorder: Style{Fg: ColorBrightBlack},
		OverlayTitle:  Style{Fg: ColorBrightCyan, Attrs: AttrBold},
		JSONKey:       Style{Fg: ColorCyan},
		JSONValue:     Style{},
	}
}

// MonoTheme is the same layout with every colour removed, for a terminal that
// does not do colour or a user who asked for none. Bold, dim and reverse still
// carry the selection and the headings, because those are structure rather
// than decoration.
func MonoTheme() Theme {
	t := DefaultTheme()
	strip := func(s Style) Style {
		s.Fg, s.Bg = ColorDefault, ColorDefault
		return s
	}
	t.Base = strip(t.Base)
	t.Dim = strip(t.Dim)
	t.PaneTitle = strip(t.PaneTitle)
	t.Rule = strip(t.Rule)
	t.TableHeader = strip(t.TableHeader)
	t.TableRow = strip(t.TableRow)
	t.TableSelected = strip(t.TableSelected)
	t.Running = strip(t.Running)
	t.Paused = strip(t.Paused)
	t.Exited = strip(t.Exited).With(AttrDim)
	t.Unhealthy = strip(t.Unhealthy)
	t.TabActive = strip(t.TabActive)
	t.TabInactive = strip(t.TabInactive).With(AttrDim)
	t.Spark = strip(t.Spark)
	t.Event = strip(t.Event)
	t.EventAction = strip(t.EventAction).With(AttrBold)
	t.Status = strip(t.Status)
	t.StatusKey = strip(t.StatusKey)
	t.StatusWarn = strip(t.StatusWarn)
	t.Warn = strip(t.Warn).With(AttrBold)
	t.Error = strip(t.Error)
	t.Prompt = strip(t.Prompt)
	t.OverlayText = strip(t.OverlayText)
	t.OverlayBorder = strip(t.OverlayBorder)
	t.OverlayTitle = strip(t.OverlayTitle)
	t.JSONKey = strip(t.JSONKey).With(AttrBold)
	t.JSONValue = strip(t.JSONValue)
	return t
}

// stateStyle picks the colour for a container in a given state.
func (t Theme) stateStyle(c types.Container) Style {
	if c.Health != nil && c.Health.Status == "unhealthy" {
		return t.Unhealthy
	}
	switch c.State {
	case types.StateRunning:
		return t.Running
	case types.StatePaused, types.StateRestarting:
		return t.Paused
	case types.StateExited, types.StateDead:
		return t.Exited
	default:
		return t.Base
	}
}
