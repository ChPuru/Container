package tui

import (
	"math"
	"strings"
	"testing"
)

func TestSparklineScaled(t *testing.T) {
	tests := []struct {
		name     string
		vals     []float64
		width    int
		min, max float64
		want     string
	}{
		{
			name:  "no samples is blank, not empty",
			vals:  nil,
			width: 5,
			want:  "     ",
		},
		{
			name:  "all zero renders as the lowest block",
			vals:  []float64{0, 0, 0},
			width: 3,
			want:  "▁▁▁",
		},
		{
			name:  "a constant series has no range to show",
			vals:  []float64{7, 7, 7},
			width: 3,
			min:   7,
			max:   7,
			want:  "▁▁▁",
		},
		{
			name:  "a single sample sits at the right-hand edge",
			vals:  []float64{100},
			width: 4,
			max:   100,
			want:  "   █",
		},
		{
			name:  "the scale spans the range",
			vals:  []float64{0, 50, 100},
			width: 3,
			max:   100,
			want:  "▁▅█",
		},
		{
			name:  "only the newest samples are shown",
			vals:  []float64{1, 2, 3, 4},
			width: 2,
			max:   4,
			want:  "▆█",
		},
		{
			name:  "values above the top are clamped",
			vals:  []float64{200},
			width: 1,
			max:   100,
			want:  "█",
		},
		{
			name:  "values below the bottom are clamped",
			vals:  []float64{-5},
			width: 1,
			max:   100,
			want:  "▁",
		},
		{
			name:  "no width renders nothing",
			vals:  []float64{1, 2},
			width: 0,
			max:   2,
			want:  "",
		},
		{
			name:  "NaN and infinity sit at the bottom",
			vals:  []float64{math.NaN(), math.Inf(1), 4},
			width: 3,
			max:   4,
			want:  "▁▁█",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SparklineScaled(tc.vals, tc.width, tc.min, tc.max)
			if got != tc.want {
				t.Errorf("SparklineScaled(%v, %d, %v, %v) = %q, want %q",
					tc.vals, tc.width, tc.min, tc.max, got, tc.want)
			}
			if n := len([]rune(got)); n != max(tc.width, 0) {
				t.Errorf("sparkline is %d cells wide, want %d", n, tc.width)
			}
		})
	}
}

func TestSparklineAutoScales(t *testing.T) {
	tests := []struct {
		name  string
		vals  []float64
		width int
		want  string
	}{
		{"auto scale peaks at the largest sample", []float64{0, 5, 10}, 3, "▁▅█"},
		{"a flat non-zero series is flat", []float64{3, 3, 3}, 3, "███"},
		{"all zero", []float64{0, 0}, 2, "▁▁"},
		{"single sample", []float64{42}, 3, "  █"},
		{"no samples", nil, 3, "   "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sparkline(tc.vals, tc.width); got != tc.want {
				t.Errorf("Sparkline(%v, %d) = %q, want %q", tc.vals, tc.width, got, tc.want)
			}
		})
	}
}

func TestSparkbarRender(t *testing.T) {
	// At twenty cells: "cpu " takes four, the value and its space take
	// four, and the twelve left over hold a line that is nine cells of
	// padding and three samples.
	wide := "cpu " + strings.Repeat(" ", 9) + "▁▅█ 50%"
	tests := []struct {
		name  string
		width int
		want  string
	}{
		{"wide enough for a line", 20, wide},
		{"too narrow for a line falls back to the number", 7, "cpu 50%"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBuffer(tc.width, 1)
			bar := Sparkbar{
				Label:   "cpu",
				Values:  []float64{0, 50, 100},
				Current: "50%",
				Max:     100,
			}
			if got := bar.Render(b, b.Bounds()); got != 1 {
				t.Fatalf("Render used %d rows, want 1", got)
			}
			if got := b.Line(0); got != tc.want {
				t.Errorf("line = %q, want %q", got, tc.want)
			}
		})
	}
}
