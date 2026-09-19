package tui

import (
	"bytes"
	"strings"
	"testing"
)

// countMoves counts cursor-position sequences, which is how many separate
// regions the renderer decided to write.
func countMoves(s string) int {
	n := 0
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '\x1b' && s[i+1] == '[' && strings.ContainsRune(s[i:min(i+12, len(s))], 'H') {
			// Only count sequences whose final byte is H.
			for j := i + 2; j < len(s); j++ {
				c := s[j]
				if c >= '0' && c <= '9' || c == ';' {
					continue
				}
				if c == 'H' {
					n++
				}
				break
			}
		}
	}
	return n
}

func TestRendererFirstFramePaintsEverything(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out)

	b := NewBuffer(10, 2)
	b.DrawText(0, 0, "hello", Style{})
	if err := r.Render(b); err != nil {
		t.Fatalf("render: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "\x1b[2J") {
		t.Errorf("first frame must clear the screen, got %q", got)
	}
	if !strings.Contains(got, "hello") {
		t.Errorf("first frame must paint the text, got %q", got)
	}
}

func TestRendererDiffWritesOnlyChangedCells(t *testing.T) {
	tests := []struct {
		name     string
		change   func(b Buffer)
		want     string
		wantMove int
	}{
		{
			name:     "one cell on the second row",
			change:   func(b Buffer) { b.Set(2, 1, Cell{Rune: 'X'}) },
			want:     "\x1b[2;3HX",
			wantMove: 1,
		},
		{
			name: "two cells one apart are written as one run",
			change: func(b Buffer) {
				b.Set(0, 1, Cell{Rune: 'a'})
				b.Set(2, 1, Cell{Rune: 'c'})
			},
			want:     "\x1b[2;1Ha c",
			wantMove: 1,
		},
		{
			name: "two cells far apart are two runs",
			change: func(b Buffer) {
				b.Set(0, 1, Cell{Rune: 'a'})
				b.Set(9, 1, Cell{Rune: 'z'})
			},
			wantMove: 2,
		},
		{
			name:     "nothing changed writes nothing",
			change:   func(b Buffer) {},
			want:     "",
			wantMove: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			r := NewRenderer(&out)

			first := NewBuffer(10, 2)
			first.DrawText(0, 0, "hello", Style{})
			if err := r.Render(first); err != nil {
				t.Fatalf("first render: %v", err)
			}
			out.Reset()

			next := first.Clone()
			tc.change(next)
			if err := r.Render(next); err != nil {
				t.Fatalf("second render: %v", err)
			}

			got := out.String()
			if tc.want != "" && got != tc.want {
				t.Errorf("diff = %q, want %q", got, tc.want)
			}
			if tc.want == "" && tc.wantMove == 0 && got != "" {
				t.Errorf("diff = %q, want nothing written", got)
			}
			if n := countMoves(got); n != tc.wantMove {
				t.Errorf("cursor moves = %d, want %d (output %q)", n, tc.wantMove, got)
			}
			if strings.Contains(got, "hello") {
				t.Errorf("unchanged row was repainted: %q", got)
			}
			if strings.Contains(got, "\x1b[2J") {
				t.Errorf("diff must not clear the screen: %q", got)
			}
		})
	}
}

func TestRendererStyleChangeEmitsSGROnce(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out)
	base := NewBuffer(6, 1)
	if err := r.Render(base); err != nil {
		t.Fatalf("render: %v", err)
	}
	out.Reset()

	next := base.Clone()
	st := Style{Fg: ColorRed, Attrs: AttrBold}
	next.DrawText(0, 0, "ab", st)
	if err := r.Render(next); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := out.String()
	if n := strings.Count(got, "\x1b[0;1;31m"); n != 1 {
		t.Errorf("SGR emitted %d times, want once: %q", n, got)
	}
	if !strings.HasSuffix(got, "ab") {
		t.Errorf("text not written last: %q", got)
	}
}

func TestRendererNoColorDropsColours(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out)
	r.SetNoColor(true)

	b := NewBuffer(4, 1)
	b.DrawText(0, 0, "ab", Style{Fg: ColorRed, Attrs: AttrReverse})
	if err := r.Render(b); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "31m") {
		t.Errorf("colour emitted in no-colour mode: %q", got)
	}
	if !strings.Contains(got, "\x1b[0;7m") {
		t.Errorf("reverse attribute lost in no-colour mode: %q", got)
	}
}

func TestRendererResizeRepaints(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out)
	if err := r.Render(NewBuffer(4, 2)); err != nil {
		t.Fatalf("render: %v", err)
	}
	out.Reset()

	wider := NewBuffer(8, 2)
	wider.DrawText(0, 0, "resized", Style{})
	if err := r.Render(wider); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "\x1b[2J") {
		t.Errorf("a size change must force a full repaint: %q", got)
	}
	if !strings.Contains(got, "resized") {
		t.Errorf("full repaint lost the content: %q", got)
	}
}

func TestRendererResetForcesFullRepaint(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out)
	b := NewBuffer(5, 1)
	b.DrawText(0, 0, "abc", Style{})
	if err := r.Render(b); err != nil {
		t.Fatalf("render: %v", err)
	}
	out.Reset()

	r.Reset()
	if err := r.Render(b); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "abc") {
		t.Errorf("after Reset the frame must be repainted: %q", got)
	}
}
