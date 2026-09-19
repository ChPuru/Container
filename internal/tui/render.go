package tui

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
)

// Renderer turns back buffers into terminal writes.
//
// It keeps the last frame it painted and, on every [Renderer.Render], writes
// only the cells that differ. That is the whole reason this package composes
// into a [Buffer] instead of printing as it goes: at one poll per second a
// dashboard that repaints the screen every tick flickers, scrolls the
// scrollback of anything that is not on the alternate screen, and makes an
// ssh session over a slow link unusable, while a diff of a frame where one
// CPU percentage moved is a few dozen bytes.
//
// A Renderer is not safe for concurrent use. Exactly one goroutine may render,
// which is the rule the whole package is built around.
type Renderer struct {
	w   io.Writer
	out bytes.Buffer

	prev Buffer

	// noColor drops colour parameters from the emitted SGR sequences but
	// keeps bold, dim, reverse and underline, so a monochrome terminal or a
	// NO_COLOR user still sees the selection.
	noColor bool

	// cur is the style the terminal is currently in, and curKnown says
	// whether that is known at all. Both are reset at the start of every
	// frame because anything may have written to the terminal in between.
	cur      Style
	curKnown bool

	// curX and curY track where the terminal's cursor is, so a run that
	// continues exactly where the last one stopped needs no cursor move.
	curX, curY int
	posKnown   bool
}

// runGap is the number of unchanged cells that must separate two changed runs
// before it is worth emitting a cursor move rather than simply repainting the
// cells in between. A cursor move costs at least six bytes, so anything under
// four unchanged cells is cheaper to overwrite.
const runGap = 4

// NewRenderer returns a Renderer that writes to w. The first
// [Renderer.Render] paints every cell, because nothing is known about the
// screen yet.
func NewRenderer(w io.Writer) *Renderer {
	return &Renderer{w: w}
}

// SetNoColor selects monochrome output: attributes are still emitted, colours
// are not. It takes effect on the next full repaint, so it also calls
// [Renderer.Reset].
func (r *Renderer) SetNoColor(v bool) {
	r.noColor = v
	r.Reset()
}

// Reset discards what the Renderer believes is on screen, so the next render
// repaints everything. Call it after anything else has written to the
// terminal: a resize, a suspend for an interactive exec, or a resume from
// SIGCONT.
func (r *Renderer) Reset() {
	r.prev = nil
	r.curKnown = false
	r.posKnown = false
}

// Render writes the difference between the previous frame and next, and
// remembers next as the new previous frame. The buffer is cloned, so the
// caller may keep drawing into it.
func (r *Renderer) Render(next Buffer) error {
	r.out.Reset()

	full := r.prev == nil ||
		r.prev.Width() != next.Width() ||
		r.prev.Height() != next.Height()
	if full {
		// The geometry changed or nothing is known: clear and paint
		// everything. Erasing first stops stale cells surviving in a
		// region the new frame does not write.
		r.out.WriteString("\x1b[m\x1b[2J\x1b[H")
		r.prev = NewBuffer(next.Width(), next.Height())
		// The erase leaves every cell blank, which is exactly what the
		// fresh prev buffer says, so the diff below paints the frame.
		r.cur = Style{}
		r.curKnown = true
		r.curX, r.curY = 0, 0
		r.posKnown = true
	}

	for y := 0; y < next.Height(); y++ {
		r.renderRow(y, r.prev[y], next[y])
	}

	r.prev = next.Clone()

	if r.out.Len() == 0 {
		return nil
	}
	if _, err := r.w.Write(r.out.Bytes()); err != nil {
		return fmt.Errorf("tui: write frame: %w", err)
	}
	return nil
}

// renderRow emits the changed runs of one row.
func (r *Renderer) renderRow(y int, prev, next []Cell) {
	x := 0
	for x < len(next) {
		if x < len(prev) && prev[x] == next[x] {
			x++
			continue
		}
		start := x
		end := x + 1
		// Extend the run over further differences, absorbing short
		// stretches of unchanged cells rather than paying for a move.
		gap := 0
		for i := end; i < len(next); i++ {
			if i < len(prev) && prev[i] == next[i] {
				gap++
				if gap >= runGap {
					break
				}
				continue
			}
			gap = 0
			end = i + 1
		}
		r.emitRun(start, y, next[start:end])
		x = end
	}
}

// emitRun moves the cursor if needed and writes one run of cells.
func (r *Renderer) emitRun(x, y int, cells []Cell) {
	if !r.posKnown || r.curX != x || r.curY != y {
		r.out.WriteString("\x1b[")
		r.out.WriteString(strconv.Itoa(y + 1))
		r.out.WriteByte(';')
		r.out.WriteString(strconv.Itoa(x + 1))
		r.out.WriteByte('H')
		r.curX, r.curY = x, y
		r.posKnown = true
	}
	for _, c := range cells {
		if !r.curKnown || c.Style != r.cur {
			r.out.WriteString(r.sgr(c.Style))
			r.cur = c.Style
			r.curKnown = true
		}
		ch := c.Rune
		if ch == 0 {
			ch = ' '
		}
		r.out.WriteRune(ch)
		r.curX++
	}
}

// sgr builds the escape sequence that selects a style. It always starts from a
// reset so no attribute can leak in from whatever the terminal was doing
// before, which costs two bytes and removes a whole class of bug.
func (r *Renderer) sgr(s Style) string {
	if s == (Style{}) {
		return "\x1b[m"
	}
	var b bytes.Buffer
	b.WriteString("\x1b[0")
	if s.Attrs&AttrBold != 0 {
		b.WriteString(";1")
	}
	if s.Attrs&AttrDim != 0 {
		b.WriteString(";2")
	}
	if s.Attrs&AttrUnderline != 0 {
		b.WriteString(";4")
	}
	if s.Attrs&AttrReverse != 0 {
		b.WriteString(";7")
	}
	if !r.noColor {
		if code, ok := fgCode(s.Fg); ok {
			b.WriteByte(';')
			b.WriteString(strconv.Itoa(code))
		}
		if code, ok := bgCode(s.Bg); ok {
			b.WriteByte(';')
			b.WriteString(strconv.Itoa(code))
		}
	}
	b.WriteByte('m')
	return b.String()
}

// fgCode maps a colour to its SGR foreground parameter.
func fgCode(c Color) (int, bool) {
	switch {
	case c == ColorDefault:
		return 0, false
	case c <= ColorWhite:
		return 30 + int(c) - 1, true
	case c <= ColorBrightWhite:
		return 90 + int(c) - int(ColorBrightBlack), true
	}
	return 0, false
}

// bgCode maps a colour to its SGR background parameter.
func bgCode(c Color) (int, bool) {
	code, ok := fgCode(c)
	if !ok {
		return 0, false
	}
	return code + 10, true
}
