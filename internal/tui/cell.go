// Package tui is hull's full-screen terminal dashboard, the thing behind
// "hull ui".
//
// It is written directly on golang.org/x/term plus raw ANSI, with no widget
// framework underneath, for three reasons: hull ships no new modules, the
// dashboard has to build for windows as well as linux, and the rendering
// strategy matters more than any framework's API. Every frame is composed into
// a back buffer of [Cell] values and then diffed against the previous frame by
// [Renderer], so a tick that changes one CPU percentage writes a dozen bytes
// rather than repainting the screen. A full redraw every second flickers,
// burns CPU and makes a remote session unusable.
//
// The package splits into three layers that can be reasoned about separately:
//
//   - the grid: [Buffer], [Cell], [Rect] and [Style] - a pure data structure
//     with no terminal anywhere near it;
//   - the widgets: [Table], [Sparkline], [Tabs] and [Overlay] - each one draws
//     into a [Buffer] at a [Rect], so a test can assert on the characters that
//     came out without a pty;
//   - the app: [Model] holds the state, [Run] and [RunWith] own the terminal,
//     one goroutine per data source feeds a single channel, and exactly one
//     goroutine ever touches the screen.
//
// [Run] takes hull's own *client.Client and is what "hull ui" calls;
// [RunWith] takes the narrow [Client] interface the dashboard actually
// consumes, which [EngineClient] implements over the Docker Engine API and a
// test implements in thirty lines.
//
// The terminal is restored from a deferred function, from a SIGINT/SIGTERM
// handler and from a panic recovery, because a dashboard that leaves the
// user's shell in raw mode with no cursor is worse than no dashboard at all.
package tui

// Color is a terminal colour. It is deliberately limited to the sixteen ANSI
// colours: they are the only ones every terminal hull runs in agrees on,
// including the Windows console with virtual-terminal processing enabled, and
// the dashboard needs contrast rather than a palette.
type Color uint8

// The sixteen ANSI colours plus ColorDefault, which leaves the terminal's own
// foreground or background in place.
const (
	ColorDefault Color = iota
	ColorBlack
	ColorRed
	ColorGreen
	ColorYellow
	ColorBlue
	ColorMagenta
	ColorCyan
	ColorWhite
	ColorBrightBlack
	ColorBrightRed
	ColorBrightGreen
	ColorBrightYellow
	ColorBrightBlue
	ColorBrightMagenta
	ColorBrightCyan
	ColorBrightWhite
)

// Attr is a set of character attributes, combined with bitwise or.
type Attr uint8

// The character attributes the dashboard uses. Nothing here is optional
// decoration: bold marks headings, reverse marks the selection, and dim marks
// data the engine could not supply.
const (
	// AttrBold renders text in bold or bright.
	AttrBold Attr = 1 << iota
	// AttrDim renders text faint.
	AttrDim
	// AttrReverse swaps foreground and background, which is how the
	// selected row and the active tab are drawn.
	AttrReverse
	// AttrUnderline underlines text.
	AttrUnderline
)

// Style is the appearance of a cell: colours plus attributes.
type Style struct {
	// Fg is the foreground colour; ColorDefault keeps the terminal's own.
	Fg Color
	// Bg is the background colour; ColorDefault keeps the terminal's own.
	Bg Color
	// Attrs is the set of character attributes.
	Attrs Attr
}

// With returns a copy of s with the given attributes added.
func (s Style) With(a Attr) Style {
	s.Attrs |= a
	return s
}

// Without returns a copy of s with the given attributes cleared.
func (s Style) Without(a Attr) Style {
	s.Attrs &^= a
	return s
}

// Foreground returns a copy of s with the given foreground colour.
func (s Style) Foreground(c Color) Style {
	s.Fg = c
	return s
}

// Background returns a copy of s with the given background colour.
func (s Style) Background(c Color) Style {
	s.Bg = c
	return s
}

// Cell is one character position on the screen: the rune that occupies it and
// how it is drawn. A zero Cell is an unpainted cell and renders as a space in
// the terminal's default colours.
type Cell struct {
	// Rune is the character in this position. The zero value and a space
	// render identically, but only equal cells are skipped by the diff, so
	// [NewBuffer] fills with spaces.
	Rune rune
	// Style is how the character is drawn.
	Style Style
}

// blank is the cell every buffer starts out full of.
var blank = Cell{Rune: ' '}

// Rect is a rectangular region of a [Buffer], in cells, with the origin at the
// top left of the screen.
type Rect struct {
	// X and Y are the top-left corner.
	X, Y int
	// W and H are the width and height in cells.
	W, H int
}

// Empty reports whether the rectangle has no area, which is the normal result
// of laying a pane out on a screen too small to hold it. Every widget returns
// immediately for an empty rect rather than clipping its way to nothing.
func (r Rect) Empty() bool { return r.W <= 0 || r.H <= 0 }

// Right returns the x coordinate one past the rectangle's last column.
func (r Rect) Right() int { return r.X + r.W }

// Bottom returns the y coordinate one past the rectangle's last row.
func (r Rect) Bottom() int { return r.Y + r.H }

// Contains reports whether the point (x, y) lies inside the rectangle.
func (r Rect) Contains(x, y int) bool {
	return x >= r.X && x < r.Right() && y >= r.Y && y < r.Bottom()
}

// Inset returns the rectangle shrunk by n cells on every side, clamped at
// empty.
func (r Rect) Inset(n int) Rect {
	out := Rect{X: r.X + n, Y: r.Y + n, W: r.W - 2*n, H: r.H - 2*n}
	if out.W < 0 {
		out.W = 0
	}
	if out.H < 0 {
		out.H = 0
	}
	return out
}

// Intersect returns the overlap of two rectangles, or an empty rectangle when
// they do not overlap.
func (r Rect) Intersect(o Rect) Rect {
	x := max(r.X, o.X)
	y := max(r.Y, o.Y)
	right := min(r.Right(), o.Right())
	bottom := min(r.Bottom(), o.Bottom())
	if right <= x || bottom <= y {
		return Rect{X: x, Y: y}
	}
	return Rect{X: x, Y: y, W: right - x, H: bottom - y}
}

// Buffer is a back buffer: a grid of cells addressed as Buffer[y][x], one row
// per screen line. Widgets draw into it and [Renderer] diffs two of them to
// work out the smallest set of writes that turns one into the other.
//
// A slice of rows rather than one flat slice is deliberate: tests assert on
// whole lines, and a row is directly addressable.
type Buffer [][]Cell

// NewBuffer allocates a w by h buffer filled with blank cells. Negative
// dimensions are treated as zero.
func NewBuffer(w, h int) Buffer {
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	b := make(Buffer, h)
	for y := range b {
		row := make([]Cell, w)
		for x := range row {
			row[x] = blank
		}
		b[y] = row
	}
	return b
}

// Width returns the buffer's width in cells.
func (b Buffer) Width() int {
	if len(b) == 0 {
		return 0
	}
	return len(b[0])
}

// Height returns the buffer's height in cells.
func (b Buffer) Height() int { return len(b) }

// Bounds returns the whole buffer as a rectangle.
func (b Buffer) Bounds() Rect { return Rect{W: b.Width(), H: b.Height()} }

// Set paints one cell. Coordinates outside the buffer are dropped, so callers
// may draw past an edge without checking first.
func (b Buffer) Set(x, y int, c Cell) {
	if y < 0 || y >= len(b) || x < 0 || x >= len(b[y]) {
		return
	}
	b[y][x] = c
}

// At returns the cell at (x, y), or a blank cell when the position lies
// outside the buffer.
func (b Buffer) At(x, y int) Cell {
	if y < 0 || y >= len(b) || x < 0 || x >= len(b[y]) {
		return blank
	}
	return b[y][x]
}

// Fill paints every cell of r with c.
func (b Buffer) Fill(r Rect, c Cell) {
	for y := r.Y; y < r.Bottom(); y++ {
		for x := r.X; x < r.Right(); x++ {
			b.Set(x, y, c)
		}
	}
}

// Clear resets every cell of the buffer to blank.
func (b Buffer) Clear() { b.Fill(b.Bounds(), blank) }

// DrawText writes s starting at (x, y) in style st and returns the x
// coordinate one past the last cell written. It never wraps: text that runs
// off the right edge of the buffer is dropped, which is what a pane wants.
func (b Buffer) DrawText(x, y int, s string, st Style) int {
	for _, r := range s {
		if r == '\t' {
			r = ' '
		}
		b.Set(x, y, Cell{Rune: r, Style: st})
		x++
	}
	return x
}

// DrawTextIn writes s at (x, y) clipped to the rectangle r, truncating with an
// ellipsis when it does not fit, and returns the x coordinate one past the
// last cell written.
func (b Buffer) DrawTextIn(r Rect, x, y int, s string, st Style) int {
	if r.Empty() || y < r.Y || y >= r.Bottom() || x >= r.Right() {
		return x
	}
	avail := r.Right() - x
	return b.DrawText(x, y, Truncate(s, avail), st)
}

// Line returns row y as a string with trailing blanks removed. It exists for
// tests, which assert on what a widget drew rather than on how it drew it.
func (b Buffer) Line(y int) string {
	if y < 0 || y >= len(b) {
		return ""
	}
	row := b[y]
	end := len(row)
	for end > 0 {
		r := row[end-1].Rune
		if r != ' ' && r != 0 {
			break
		}
		end--
	}
	out := make([]rune, 0, end)
	for _, c := range row[:end] {
		if c.Rune == 0 {
			out = append(out, ' ')
			continue
		}
		out = append(out, c.Rune)
	}
	return string(out)
}

// String renders the whole buffer as newline-separated lines, for tests and
// for golden-file comparison.
func (b Buffer) String() string {
	out := make([]byte, 0, b.Width()*b.Height())
	for y := range b {
		if y > 0 {
			out = append(out, '\n')
		}
		out = append(out, []byte(b.Line(y))...)
	}
	return string(out)
}

// Equal reports whether two buffers have the same dimensions and the same
// cells.
func (b Buffer) Equal(o Buffer) bool {
	if b.Height() != o.Height() || b.Width() != o.Width() {
		return false
	}
	for y := range b {
		for x := range b[y] {
			if b[y][x] != o[y][x] {
				return false
			}
		}
	}
	return true
}

// Clone returns a deep copy of the buffer.
func (b Buffer) Clone() Buffer {
	out := make(Buffer, len(b))
	for y := range b {
		row := make([]Cell, len(b[y]))
		copy(row, b[y])
		out[y] = row
	}
	return out
}
