package tui

// Overlay is a centred box drawn over the dashboard: the help screen, the
// delete confirmation and the host-warning list all use it.
//
// It clips rather than overflows. On a screen too small for the box plus its
// border, the border is dropped and the text is drawn straight over the
// dashboard, because losing the frame is better than losing the question the
// user is being asked.
type Overlay struct {
	// Title is drawn in the top border.
	Title string
	// Lines are the body, one per row. They are not wrapped here: a caller
	// that needs wrapping calls [wrapLines] against the width it wants.
	Lines []string
	// Footer is drawn in the bottom border, typically the keys that
	// dismiss the overlay.
	Footer string
	// Style paints the body, BorderStyle the frame, and TitleStyle the
	// title text.
	Style       Style
	BorderStyle Style
	TitleStyle  Style
	// Width, when positive, fixes the inner width; otherwise the box is
	// sized to its longest line.
	Width int
}

// Box-drawing runes for the overlay frame.
const (
	boxTopLeft     = '┌'
	boxTopRight    = '┐'
	boxBottomLeft  = '└'
	boxBottomRight = '┘'
	boxHorizontal  = '─'
	boxVertical    = '│'
)

// CenterRect returns a w by h rectangle centred inside area, clamped so it
// never extends outside it.
func CenterRect(area Rect, w, h int) Rect {
	if w > area.W {
		w = area.W
	}
	if h > area.H {
		h = area.H
	}
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	return Rect{
		X: area.X + (area.W-w)/2,
		Y: area.Y + (area.H-h)/2,
		W: w,
		H: h,
	}
}

// Render draws the overlay centred in area and returns the rectangle it
// occupied.
func (o Overlay) Render(b Buffer, area Rect) Rect {
	if area.Empty() {
		return Rect{}
	}
	inner := o.Width
	if inner <= 0 {
		for _, l := range o.Lines {
			if n := len([]rune(l)); n > inner {
				inner = n
			}
		}
		if n := len([]rune(o.Title)) + 2; n > inner {
			inner = n
		}
		if n := len([]rune(o.Footer)) + 2; n > inner {
			inner = n
		}
	}
	inner = clampInt(inner, 1, area.W-2)
	height := len(o.Lines)

	// Below this there is no room for a frame; draw the text alone.
	if area.W < 4 || area.H < 3 {
		box := CenterRect(area, area.W, min(height, area.H))
		b.Fill(box, Cell{Rune: ' ', Style: o.Style})
		for i, line := range o.Lines {
			if i >= box.H {
				break
			}
			b.DrawTextIn(box, box.X, box.Y+i, line, o.Style)
		}
		return box
	}

	box := CenterRect(area, inner+2, clampInt(height+2, 3, area.H))
	b.Fill(box, Cell{Rune: ' ', Style: o.Style})

	// Frame.
	top, bottom := box.Y, box.Bottom()-1
	for x := box.X; x < box.Right(); x++ {
		b.Set(x, top, Cell{Rune: boxHorizontal, Style: o.BorderStyle})
		b.Set(x, bottom, Cell{Rune: boxHorizontal, Style: o.BorderStyle})
	}
	for y := top + 1; y < bottom; y++ {
		b.Set(box.X, y, Cell{Rune: boxVertical, Style: o.BorderStyle})
		b.Set(box.Right()-1, y, Cell{Rune: boxVertical, Style: o.BorderStyle})
	}
	b.Set(box.X, top, Cell{Rune: boxTopLeft, Style: o.BorderStyle})
	b.Set(box.Right()-1, top, Cell{Rune: boxTopRight, Style: o.BorderStyle})
	b.Set(box.X, bottom, Cell{Rune: boxBottomLeft, Style: o.BorderStyle})
	b.Set(box.Right()-1, bottom, Cell{Rune: boxBottomRight, Style: o.BorderStyle})

	if o.Title != "" {
		title := Truncate(" "+o.Title+" ", box.W-2)
		b.DrawText(box.X+1, top, title, o.TitleStyle)
	}
	if o.Footer != "" {
		footer := Truncate(" "+o.Footer+" ", box.W-2)
		start := box.Right() - 1 - len([]rune(footer))
		if start < box.X+1 {
			start = box.X + 1
		}
		b.DrawText(start, bottom, footer, o.BorderStyle)
	}

	body := Rect{X: box.X + 1, Y: box.Y + 1, W: box.W - 2, H: box.H - 2}
	for i, line := range o.Lines {
		if i >= body.H {
			break
		}
		b.DrawTextIn(body, body.X, body.Y+i, line, o.Style)
	}
	return box
}

// helpLines is the key map, in the order a new user should meet it. It is data
// rather than a printf so the help overlay and any future "hull ui --keys"
// cannot drift apart.
var helpLines = [][2]string{
	{"j / down", "select the next container"},
	{"k / up", "select the previous container"},
	{"g / G", "first / last container"},
	{"tab / shift-tab", "cycle the detail tabs"},
	{"1..4", "jump straight to a detail tab"},
	{"l", "jump to the logs tab"},
	{"/", "filter by name, id, image or state"},
	{"s / S", "stop / start the selection"},
	{"r", "restart the selection"},
	{"p", "pause or unpause the selection"},
	{"d", "delete the selection (asks first)"},
	{"e", "open a shell in the selection"},
	{"w", "show the host warnings"},
	{"page up / down", "scroll the detail pane"},
	{"?", "this help"},
	{"q / ctrl-c", "quit"},
}

// helpOverlay builds the help overlay for a given width.
func helpOverlay(th Theme, width int) Overlay {
	keyW := 0
	for _, kv := range helpLines {
		if n := len([]rune(kv[0])); n > keyW {
			keyW = n
		}
	}
	lines := make([]string, 0, len(helpLines)+2)
	for _, kv := range helpLines {
		lines = append(lines, Pad(kv[0], keyW, AlignRight)+"  "+kv[1])
	}
	lines = append(lines, "", Truncate("hull ui - one screen for containers, logs, stats and events", width))
	return Overlay{
		Title:       "keys",
		Lines:       lines,
		Footer:      "any key closes",
		Style:       th.OverlayText,
		BorderStyle: th.OverlayBorder,
		TitleStyle:  th.OverlayTitle,
	}
}
