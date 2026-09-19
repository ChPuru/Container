package tui

import "testing"

func TestBufferBasics(t *testing.T) {
	b := NewBuffer(4, 2)
	if b.Width() != 4 || b.Height() != 2 {
		t.Fatalf("buffer is %dx%d, want 4x2", b.Width(), b.Height())
	}
	if got := b.At(0, 0).Rune; got != ' ' {
		t.Errorf("new buffer cell = %q, want a space", got)
	}
	if got := b.At(-1, 0).Rune; got != ' ' {
		t.Errorf("out-of-bounds read = %q, want a blank cell", got)
	}
	// Writing outside the buffer is a no-op rather than a panic, so a
	// widget may draw past an edge without checking first.
	b.Set(99, 99, Cell{Rune: 'x'})
	b.Set(-1, -1, Cell{Rune: 'x'})
	if b.String() != "\n" {
		t.Errorf("out-of-bounds writes landed somewhere: %q", b.String())
	}
}

func TestBufferNegativeDimensions(t *testing.T) {
	b := NewBuffer(-3, -1)
	if b.Width() != 0 || b.Height() != 0 {
		t.Errorf("negative dimensions gave a %dx%d buffer", b.Width(), b.Height())
	}
}

func TestBufferDrawText(t *testing.T) {
	tests := []struct {
		name string
		x    int
		text string
		want string
	}{
		{"from the left", 0, "hello", "hello"},
		{"offset", 2, "hi", "  hi"},
		{"clipped at the right edge", 6, "spill", "      sp"},
		{"tabs become spaces", 0, "a\tb", "a b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBuffer(8, 1)
			b.DrawText(tc.x, 0, tc.text, Style{})
			if got := b.Line(0); got != tc.want {
				t.Errorf("line = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBufferDrawTextInTruncates(t *testing.T) {
	b := NewBuffer(10, 1)
	r := Rect{X: 2, Y: 0, W: 4, H: 1}
	b.DrawTextIn(r, r.X, 0, "abcdefgh", Style{})
	if got, want := b.Line(0), "  abc…"; got != want {
		t.Errorf("line = %q, want %q", got, want)
	}
}

func TestBufferFillAndClear(t *testing.T) {
	b := NewBuffer(4, 2)
	b.Fill(Rect{X: 1, Y: 0, W: 2, H: 2}, Cell{Rune: '#'})
	if got, want := b.Line(0), " ##"; got != want {
		t.Errorf("line = %q, want %q", got, want)
	}
	b.Clear()
	if got := b.String(); got != "\n" {
		t.Errorf("cleared buffer = %q", got)
	}
}

func TestBufferCloneAndEqual(t *testing.T) {
	a := NewBuffer(3, 2)
	a.DrawText(0, 0, "ab", Style{Fg: ColorRed})
	c := a.Clone()
	if !a.Equal(c) {
		t.Fatal("a clone must equal its original")
	}
	c.Set(0, 0, Cell{Rune: 'z'})
	if a.Equal(c) {
		t.Error("the clone shares memory with the original")
	}
	if a.Equal(NewBuffer(4, 2)) {
		t.Error("buffers of different sizes must not compare equal")
	}
	// A cell that differs only in style is a different cell, or the diff
	// renderer would never repaint a colour change.
	d := a.Clone()
	d.Set(0, 0, Cell{Rune: 'a', Style: Style{Fg: ColorBlue}})
	if a.Equal(d) {
		t.Error("a style change must count as a difference")
	}
}

func TestRectGeometry(t *testing.T) {
	r := Rect{X: 2, Y: 3, W: 10, H: 5}
	if r.Right() != 12 || r.Bottom() != 8 {
		t.Errorf("right/bottom = %d/%d, want 12/8", r.Right(), r.Bottom())
	}
	if !r.Contains(2, 3) || r.Contains(12, 3) || r.Contains(2, 8) {
		t.Error("Contains is off by one")
	}
	if got := r.Inset(1); got != (Rect{X: 3, Y: 4, W: 8, H: 3}) {
		t.Errorf("Inset(1) = %+v", got)
	}
	if got := r.Inset(99); !got.Empty() {
		t.Errorf("Inset past the middle = %+v, want empty", got)
	}
	if got := (Rect{W: 4, H: 4}).Intersect(Rect{X: 2, Y: 2, W: 4, H: 4}); got != (Rect{X: 2, Y: 2, W: 2, H: 2}) {
		t.Errorf("Intersect = %+v", got)
	}
	if got := (Rect{W: 2, H: 2}).Intersect(Rect{X: 5, Y: 5, W: 2, H: 2}); !got.Empty() {
		t.Errorf("disjoint Intersect = %+v, want empty", got)
	}
	if !(Rect{W: 0, H: 5}).Empty() || !(Rect{W: 5, H: -1}).Empty() {
		t.Error("Empty missed a degenerate rectangle")
	}
}

func TestStyleHelpers(t *testing.T) {
	s := Style{}.Foreground(ColorRed).Background(ColorBlue).With(AttrBold | AttrDim)
	if s.Fg != ColorRed || s.Bg != ColorBlue {
		t.Errorf("colours = %v/%v", s.Fg, s.Bg)
	}
	if s.Attrs&AttrBold == 0 || s.Attrs&AttrDim == 0 {
		t.Error("attributes not set")
	}
	if got := s.Without(AttrDim); got.Attrs&AttrDim != 0 {
		t.Error("Without did not clear the attribute")
	}
	if s.Attrs&AttrDim == 0 {
		t.Error("Without mutated the receiver")
	}
}

func TestTabsRender(t *testing.T) {
	tests := []struct {
		name  string
		width int
		want  string
	}{
		{"every tab fits", 40, " Logs │ Stats │ Inspect │ Ports"},
		{"too narrow shows the active tab and a counter", 12, " Stats  2/4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBuffer(tc.width, 1)
			Tabs{Titles: tabTitles, Active: int(TabStats)}.Render(b, b.Bounds())
			if got := b.Line(0); got != tc.want {
				t.Errorf("tab bar = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTabsMarksTheActiveTab(t *testing.T) {
	b := NewBuffer(40, 1)
	Tabs{
		Titles:      tabTitles,
		Active:      1,
		ActiveStyle: Style{Attrs: AttrReverse},
	}.Render(b, b.Bounds())
	line := b.Line(0)
	idx := indexRune(line, 'S')
	if idx < 0 {
		t.Fatalf("Stats not drawn: %q", line)
	}
	if b.At(idx, 0).Style.Attrs&AttrReverse == 0 {
		t.Errorf("the active tab is not highlighted")
	}
	if b.At(1, 0).Style.Attrs&AttrReverse != 0 {
		t.Errorf("an inactive tab is highlighted")
	}
}

func TestOverlayRender(t *testing.T) {
	b := NewBuffer(20, 7)
	o := Overlay{
		Title:  "confirm",
		Lines:  []string{"delete web?"},
		Footer: "y / n",
	}
	box := o.Render(b, b.Bounds())
	if box.W < 13 || box.H != 3 {
		t.Fatalf("box = %+v, want it sized to its content", box)
	}
	if b.At(box.X, box.Y).Rune != boxTopLeft {
		t.Errorf("no frame corner at the top left")
	}
	if b.At(box.Right()-1, box.Bottom()-1).Rune != boxBottomRight {
		t.Errorf("no frame corner at the bottom right")
	}
	if !contains(b.String(), "delete web?") {
		t.Errorf("body missing:\n%s", b.String())
	}
	if !contains(b.String(), "confirm") {
		t.Errorf("title missing:\n%s", b.String())
	}
}

func TestOverlayTooSmallDropsTheFrame(t *testing.T) {
	b := NewBuffer(3, 2)
	o := Overlay{Title: "t", Lines: []string{"hi"}}
	box := o.Render(b, b.Bounds())
	if box.Empty() {
		t.Fatal("overlay drew nothing at all")
	}
	if !contains(b.String(), "hi") {
		t.Errorf("text lost on a tiny screen: %q", b.String())
	}
}

func TestCenterRect(t *testing.T) {
	area := Rect{W: 10, H: 10}
	if got := CenterRect(area, 4, 2); got != (Rect{X: 3, Y: 4, W: 4, H: 2}) {
		t.Errorf("CenterRect = %+v", got)
	}
	if got := CenterRect(area, 40, 40); got != (Rect{W: 10, H: 10}) {
		t.Errorf("CenterRect must clamp to the area, got %+v", got)
	}
}

func TestPaneTitle(t *testing.T) {
	b := NewBuffer(20, 1)
	PaneTitle(b, b.Bounds(), "events", "3", Style{}, Style{})
	line := b.Line(0)
	if !contains(line, "events") || !contains(line, "─") {
		t.Errorf("pane title = %q, want a caption and a rule", line)
	}
	if line[len(line)-1] != '3' {
		t.Errorf("pane title = %q, want the detail at the right", line)
	}
}

// contains is strings.Contains without the import.
func contains(haystack, needle string) bool {
	return indexOf(haystack, needle) >= 0
}

// indexOf is strings.Index without the import.
func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// indexRune returns the cell index of the first occurrence of r.
func indexRune(s string, r rune) int {
	for i, c := range []rune(s) {
		if c == r {
			return i
		}
	}
	return -1
}
