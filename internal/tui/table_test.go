package tui

import (
	"reflect"
	"testing"
)

func TestColumnLayout(t *testing.T) {
	tests := []struct {
		name    string
		cols    []Column
		natural []int
		avail   int
		gap     int
		want    []int
	}{
		{
			name:  "weighted columns share the surplus exactly",
			cols:  []Column{{Title: "a", Min: 5, Weight: 1}, {Title: "b", Min: 5, Weight: 1}},
			avail: 13,
			gap:   1,
			want:  []int{6, 6},
		},
		{
			name: "content widens a column up to its cap",
			cols: []Column{{Title: "name", Min: 4, Max: 12}},
			// The data is wider than the cap, so the cap wins and the
			// cells are truncated rather than the table overflowing.
			natural: []int{40},
			avail:   40,
			gap:     1,
			want:    []int{12},
		},
		{
			name: "the highest priority column is dropped first",
			cols: []Column{
				{Title: "a", Min: 10},
				{Title: "b", Min: 10, Priority: 1},
				{Title: "c", Min: 10, Priority: 2},
			},
			avail: 21,
			gap:   1,
			want:  []int{10, 10, 0},
		},
		{
			name: "two columns are dropped when one is not enough",
			cols: []Column{
				{Title: "a", Min: 10},
				{Title: "b", Min: 10, Priority: 1},
				{Title: "c", Min: 10, Priority: 2},
			},
			// Nothing here has a weight, so the survivor keeps its own
			// width rather than stretching into the space it freed.
			avail: 12,
			gap:   1,
			want:  []int{10, 0, 0},
		},
		{
			name:  "undroppable columns are squeezed proportionally",
			cols:  []Column{{Title: "a", Min: 10}, {Title: "b", Min: 10}},
			avail: 15,
			gap:   1,
			want:  []int{7, 7},
		},
		{
			name:  "a single column takes what there is",
			cols:  []Column{{Title: "only", Min: 10}},
			avail: 4,
			gap:   1,
			want:  []int{4},
		},
		{
			name:  "no space at all drops everything",
			cols:  []Column{{Title: "a", Min: 4}},
			avail: 0,
			gap:   1,
			want:  []int{0},
		},
		{
			name:  "a title wider than Min sets the floor",
			cols:  []Column{{Title: "identifier", Min: 2}},
			avail: 30,
			gap:   1,
			want:  []int{10},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ColumnLayout(tc.cols, tc.natural, tc.avail, tc.gap)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ColumnLayout() = %v, want %v", got, tc.want)
			}
			// Whatever the rules did, the row must still fit.
			total, n := 0, 0
			for _, w := range got {
				if w > 0 {
					total += w
					n++
				}
			}
			if n > 1 {
				total += tc.gap * (n - 1)
			}
			if total > tc.avail {
				t.Errorf("columns total %d cells, only %d available", total, tc.avail)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		width int
		want  string
	}{
		{"fits exactly", "abc", 3, "abc"},
		{"shorter than the column", "ab", 5, "ab"},
		{"cut with an ellipsis", "abcdef", 3, "ab…"},
		{"one cell is just the ellipsis", "abcd", 1, "…"},
		{"no room at all", "abcd", 0, ""},
		{"negative width", "abcd", -3, ""},
		{"multi-byte runes count as one cell", "éèêë", 3, "éè…"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Truncate(tc.in, tc.width); got != tc.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
			}
			if n := len([]rune(Truncate(tc.in, tc.width))); tc.width >= 0 && n > tc.width {
				t.Errorf("Truncate(%q, %d) is %d cells wide", tc.in, tc.width, n)
			}
		})
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		width int
		align Align
		want  string
	}{
		{"left", "ab", 5, AlignLeft, "ab   "},
		{"right", "ab", 5, AlignRight, "   ab"},
		{"centre", "ab", 6, AlignCenter, "  ab  "},
		{"too long is truncated", "abcdef", 4, AlignLeft, "abc…"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Pad(tc.in, tc.width, tc.align)
			if got != tc.want {
				t.Errorf("Pad(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
			}
			if len([]rune(got)) != tc.width {
				t.Errorf("Pad(%q, %d) is %d cells wide", tc.in, tc.width, len([]rune(got)))
			}
		})
	}
}

func TestTableRenderTruncatesCells(t *testing.T) {
	tbl := &Table{
		Columns: []Column{
			{Title: "name", Min: 6, Max: 6},
			{Title: "state", Min: 7, Max: 7},
		},
		Rows: []Row{
			{Key: "a", Cells: []string{"verylongname", "running"}},
			{Key: "b", Cells: []string{"short", "exited"}},
		},
		Gap: 1,
	}
	b := NewBuffer(14, 3)
	tbl.Render(b, b.Bounds())

	if got, want := b.Line(0), "NAME   STATE"; got != want {
		t.Errorf("header = %q, want %q", got, want)
	}
	if got, want := b.Line(1), "veryl… running"; got != want {
		t.Errorf("row 0 = %q, want %q", got, want)
	}
	if got, want := b.Line(2), "short  exited"; got != want {
		t.Errorf("row 1 = %q, want %q", got, want)
	}
}

func TestTableSelectionAndScrolling(t *testing.T) {
	rows := make([]Row, 10)
	for i := range rows {
		rows[i] = Row{Key: string(rune('a' + i)), Cells: []string{string(rune('a' + i))}}
	}
	tbl := &Table{Columns: []Column{{Title: "k", Min: 3}}, Rows: rows}
	// Four lines: one header plus three data rows.
	r := Rect{W: 10, H: 4}

	if got := tbl.BodyHeight(r); got != 3 {
		t.Fatalf("BodyHeight = %d, want 3", got)
	}

	tbl.Selected = 0
	tbl.EnsureVisible(r)
	if tbl.Offset != 0 {
		t.Errorf("offset = %d, want 0 for the first row", tbl.Offset)
	}

	tbl.Selected = 5
	tbl.EnsureVisible(r)
	if tbl.Offset != 3 {
		t.Errorf("offset = %d, want 3 so row 5 is the last visible", tbl.Offset)
	}

	tbl.Selected = 99
	tbl.EnsureVisible(r)
	if tbl.Selected != 9 {
		t.Errorf("selection = %d, want it clamped to 9", tbl.Selected)
	}
	if tbl.Offset != 7 {
		t.Errorf("offset = %d, want 7", tbl.Offset)
	}

	tbl.Rows = nil
	tbl.EnsureVisible(r)
	if tbl.Selected != 0 || tbl.Offset != 0 {
		t.Errorf("empty table left selection %d offset %d", tbl.Selected, tbl.Offset)
	}
}

func TestTableSelectedRowFillsTheWidth(t *testing.T) {
	tbl := &Table{
		Columns:       []Column{{Title: "k", Min: 3}},
		Rows:          []Row{{Key: "a", Cells: []string{"a"}}, {Key: "b", Cells: []string{"b"}}},
		Selected:      1,
		SelectedStyle: Style{Attrs: AttrReverse},
	}
	b := NewBuffer(8, 3)
	tbl.Render(b, b.Bounds())
	for x := 0; x < 8; x++ {
		if got := b.At(x, 2).Style.Attrs; got&AttrReverse == 0 {
			t.Fatalf("selected row cell %d is not highlighted", x)
		}
	}
	if b.At(0, 1).Style.Attrs&AttrReverse != 0 {
		t.Errorf("unselected row is highlighted")
	}
}

func TestTableHiddenHeader(t *testing.T) {
	tbl := &Table{
		Columns:    []Column{{Title: "k", Min: 3}},
		Rows:       []Row{{Key: "a", Cells: []string{"aa"}}},
		HideHeader: true,
	}
	b := NewBuffer(6, 2)
	tbl.Render(b, b.Bounds())
	if got := b.Line(0); got != "aa" {
		t.Errorf("first line = %q, want the first row with no header", got)
	}
}
