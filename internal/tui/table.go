package tui

import "strings"

// Column describes one column of a [Table].
//
// Sizing is a negotiation rather than a set of fixed widths, because the same
// dashboard has to be readable at 40 columns on a split pane and at 200 on a
// wide monitor. Each column states the width it would like, the width below
// which it is useless, how eagerly it should absorb spare space, and how
// willing it is to be dropped entirely.
type Column struct {
	// Title is the header text.
	Title string
	// Min is the narrowest this column may be squeezed to before it is
	// dropped instead. Zero means the width of the title.
	Min int
	// Max caps the column even when there is space to spare. Zero means no
	// cap, which is only sensible on a column with a Weight.
	Max int
	// Weight is this column's share of the space left over once every
	// column has its desired width. Zero means the column never stretches.
	Weight int
	// Align selects how the cell text sits in the column.
	Align Align
	// Priority orders columns for removal on a narrow screen: the highest
	// priority is dropped first, and ties are broken rightmost-first. A
	// column with priority 0 is never dropped.
	Priority int
}

// Row is one line of a [Table].
type Row struct {
	// Key identifies the row across refreshes, so the selection survives a
	// container appearing or disappearing above it.
	Key string
	// Cells holds one string per column, in column order. A short slice is
	// padded with empty cells.
	Cells []string
	// Style, when non-zero, overrides the table's row style. It is how a
	// stopped container is dimmed and an unhealthy one is coloured.
	Style Style
}

// Table is the container list: a header, a set of rows, a selection and a
// scroll offset. It draws into a [Buffer] and holds no terminal state, so
// every sizing and truncation rule is testable directly.
type Table struct {
	// Columns describes the columns, left to right.
	Columns []Column
	// Rows are the data rows.
	Rows []Row
	// Selected is the index of the selected row in Rows.
	Selected int
	// Offset is the index of the first row drawn, maintained by
	// [Table.EnsureVisible].
	Offset int
	// Gap is the number of blank cells between columns. Zero means one.
	Gap int
	// HeaderStyle, RowStyle and SelectedStyle paint the header, an ordinary
	// row and the selected row.
	HeaderStyle   Style
	RowStyle      Style
	SelectedStyle Style
	// HideHeader suppresses the header row, which the narrow layout does
	// for a two-line table where the header would cost half the pane.
	HideHeader bool
}

// minColumnWidth is the floor a column is squeezed to before being dropped.
// Three cells hold one character and an ellipsis with a gap, which is the
// least that still says a column exists.
const minColumnWidth = 3

// ColumnLayout computes the on-screen width of every column for a table body
// avail cells wide, with gap cells between columns.
//
// natural is the widest cell each column holds, which the caller measures from
// the data; it may be nil, in which case the title width is used. A returned
// width of zero means the column was dropped because the screen is too narrow
// to carry it.
//
// The rules, in order: every visible column gets at least its desired width if
// it fits; otherwise the highest-priority columns are dropped one at a time;
// if it still does not fit, what is left is squeezed proportionally down to
// [minColumnWidth]; and any space left over is shared between the weighted
// columns.
func ColumnLayout(cols []Column, natural []int, avail, gap int) []int {
	widths := make([]int, len(cols))
	if len(cols) == 0 || avail <= 0 {
		return widths
	}
	if gap < 0 {
		gap = 0
	}

	desired := make([]int, len(cols))
	for i, c := range cols {
		want := len([]rune(c.Title))
		if natural != nil && i < len(natural) && natural[i] > want {
			want = natural[i]
		}
		if c.Min > want {
			want = c.Min
		}
		if c.Max > 0 && want > c.Max {
			want = c.Max
		}
		if want < 1 {
			want = 1
		}
		desired[i] = want
	}

	visible := make([]bool, len(cols))
	for i := range visible {
		visible[i] = true
	}

	total := func() int {
		sum, n := 0, 0
		for i := range cols {
			if !visible[i] {
				continue
			}
			sum += desired[i]
			n++
		}
		if n > 1 {
			sum += gap * (n - 1)
		}
		return sum
	}

	// Drop columns, highest priority first, until what is left fits or only
	// one column remains.
	for total() > avail {
		victim, worst := -1, 0
		count := 0
		for i, c := range cols {
			if !visible[i] {
				continue
			}
			count++
			if c.Priority > 0 && c.Priority >= worst {
				victim, worst = i, c.Priority
			}
		}
		if victim < 0 || count <= 1 {
			break
		}
		visible[victim] = false
	}

	// Squeeze what is left.
	if over := total() - avail; over > 0 {
		slack := 0
		for i := range cols {
			if visible[i] && desired[i] > minColumnWidth {
				slack += desired[i] - minColumnWidth
			}
		}
		for i := range cols {
			if !visible[i] || slack <= 0 {
				continue
			}
			room := desired[i] - minColumnWidth
			if room <= 0 {
				continue
			}
			cut := over * room / slack
			if cut > room {
				cut = room
			}
			desired[i] -= cut
		}
		// Rounding can leave a cell or two over; take them from the
		// widest visible column, one at a time.
		for total() > avail {
			widest, wi := 0, -1
			for i := range cols {
				if visible[i] && desired[i] > widest {
					widest, wi = desired[i], i
				}
			}
			if wi < 0 || desired[wi] <= 1 {
				break
			}
			desired[wi]--
		}
	}

	// Share out anything left over between the weighted columns.
	if spare := avail - total(); spare > 0 {
		weight := 0
		for i, c := range cols {
			if visible[i] {
				weight += c.Weight
			}
		}
		if weight > 0 {
			given := 0
			first := -1
			for i, c := range cols {
				if !visible[i] || c.Weight == 0 {
					continue
				}
				if first < 0 {
					first = i
				}
				add := spare * c.Weight / weight
				if c.Max > 0 && desired[i]+add > c.Max {
					add = c.Max - desired[i]
				}
				if add < 0 {
					add = 0
				}
				desired[i] += add
				given += add
			}
			if rem := spare - given; rem > 0 && first >= 0 {
				c := cols[first]
				if c.Max == 0 || desired[first]+rem <= c.Max {
					desired[first] += rem
				}
			}
		}
	}

	for i := range cols {
		if visible[i] {
			widths[i] = desired[i]
		}
	}
	return widths
}

// gapWidth returns the configured gap, defaulting to one cell.
func (t *Table) gapWidth() int {
	if t.Gap <= 0 {
		return 1
	}
	return t.Gap
}

// naturalWidths measures the widest cell in every column.
func (t *Table) naturalWidths() []int {
	out := make([]int, len(t.Columns))
	for _, row := range t.Rows {
		for i := range t.Columns {
			if i >= len(row.Cells) {
				break
			}
			if n := len([]rune(row.Cells[i])); n > out[i] {
				out[i] = n
			}
		}
	}
	return out
}

// BodyHeight returns how many data rows fit in r, once the header has taken
// its row.
func (t *Table) BodyHeight(r Rect) int {
	h := r.H
	if !t.HideHeader {
		h--
	}
	if h < 0 {
		return 0
	}
	return h
}

// EnsureVisible scrolls so the selected row is on screen, clamping the
// selection into the row range first. Call it after changing Selected or after
// the row set changes.
func (t *Table) EnsureVisible(r Rect) {
	if len(t.Rows) == 0 {
		t.Selected, t.Offset = 0, 0
		return
	}
	t.Selected = clampInt(t.Selected, 0, len(t.Rows)-1)
	h := t.BodyHeight(r)
	if h <= 0 {
		t.Offset = t.Selected
		return
	}
	if t.Selected < t.Offset {
		t.Offset = t.Selected
	}
	if t.Selected >= t.Offset+h {
		t.Offset = t.Selected - h + 1
	}
	maxOffset := len(t.Rows) - h
	if maxOffset < 0 {
		maxOffset = 0
	}
	t.Offset = clampInt(t.Offset, 0, maxOffset)
}

// Render draws the table into b at r.
func (t *Table) Render(b Buffer, r Rect) {
	if r.Empty() || len(t.Columns) == 0 {
		return
	}
	gap := t.gapWidth()
	widths := ColumnLayout(t.Columns, t.naturalWidths(), r.W, gap)

	y := r.Y
	if !t.HideHeader {
		t.drawRow(b, r, y, t.headerCells(), widths, gap, t.HeaderStyle, false)
		y++
	}
	body := t.BodyHeight(r)
	for i := 0; i < body; i++ {
		idx := t.Offset + i
		if idx >= len(t.Rows) {
			break
		}
		row := t.Rows[idx]
		style := row.Style
		if style == (Style{}) {
			style = t.RowStyle
		}
		selected := idx == t.Selected
		if selected {
			style = t.SelectedStyle
		}
		t.drawRow(b, r, y+i, row.Cells, widths, gap, style, selected)
	}
}

// headerCells returns the column titles as a row.
func (t *Table) headerCells() []string {
	out := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		out[i] = strings.ToUpper(c.Title)
	}
	return out
}

// drawRow paints one row of cells, padding the whole width so a selected row
// highlights edge to edge rather than only under its text.
func (t *Table) drawRow(b Buffer, r Rect, y int, cells []string, widths []int, gap int, style Style, fill bool) {
	if y < r.Y || y >= r.Bottom() {
		return
	}
	if fill {
		b.Fill(Rect{X: r.X, Y: y, W: r.W, H: 1}, Cell{Rune: ' ', Style: style})
	}
	x := r.X
	for i, w := range widths {
		if w <= 0 {
			continue
		}
		if x >= r.Right() {
			break
		}
		text := ""
		if i < len(cells) {
			text = cells[i]
		}
		avail := min(w, r.Right()-x)
		b.DrawText(x, y, Pad(text, avail, t.Columns[i].Align), style)
		x += w + gap
	}
}
