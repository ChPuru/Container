package tui

import "math"

// sparkRunes are the eight one-eighth block characters, lowest first. They are
// the only glyphs the stats pane needs, and every terminal that can show the
// dashboard at all has them.
var sparkRunes = [8]rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// Sparkline renders the last width samples of vals as block characters,
// auto-scaled from zero to the largest sample.
//
// Scaling from zero rather than from the smallest sample is deliberate for
// CPU and memory: a series that wanders between 40% and 42% should look flat,
// not like a mountain range. Use [SparklineScaled] when the range is known in
// advance, such as a percentage that should always be read against 100.
func Sparkline(vals []float64, width int) string {
	maxV := 0.0
	for _, v := range vals {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		if v > maxV {
			maxV = v
		}
	}
	return SparklineScaled(vals, width, 0, maxV)
}

// SparklineScaled renders the last width samples of vals as block characters
// on a fixed scale.
//
// The result is always exactly width cells wide: a series shorter than the
// width is right-aligned and padded with spaces on the left, so a new sample
// appears at the right-hand edge and the line does not jump as the history
// fills up.
//
// Two degenerate inputs matter and both are defined rather than accidental:
//
//   - no samples at all renders as all spaces, which is what a container that
//     has never reported stats should look like;
//   - a range of zero - every sample equal, the all-zero series included -
//     renders as the lowest block, because there is no variation to show and
//     the magnitude is carried by the caption beside the line, not by a
//     sparkline that would otherwise be all full blocks.
//
// Samples that are NaN or infinite are clamped to the bottom of the scale.
func SparklineScaled(vals []float64, width int, minV, maxV float64) string {
	if width <= 0 {
		return ""
	}
	out := make([]rune, 0, width)
	if len(vals) < width {
		for i := 0; i < width-len(vals); i++ {
			out = append(out, ' ')
		}
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	span := maxV - minV
	for _, v := range vals {
		out = append(out, sparkRune(v, minV, span))
	}
	return string(out)
}

// sparkRune maps one sample onto a block character.
func sparkRune(v, minV, span float64) rune {
	if math.IsNaN(v) || math.IsInf(v, 0) || span <= 0 || v <= minV {
		return sparkRunes[0]
	}
	frac := (v - minV) / span
	idx := int(frac*float64(len(sparkRunes)-1) + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sparkRunes) {
		idx = len(sparkRunes) - 1
	}
	return sparkRunes[idx]
}

// Sparkbar is a labelled sparkline: a caption, the line itself and the current
// value, laid out on one row. It is the unit the stats tab is built from.
type Sparkbar struct {
	// Label names the series, e.g. "cpu".
	Label string
	// Values is the sample history, oldest first.
	Values []float64
	// Current is the text for the right-hand value, already formatted.
	Current string
	// Max, when positive, fixes the top of the scale; otherwise the line
	// auto-scales to its own peak.
	Max float64
	// Style and LineStyle paint the caption and the line.
	Style     Style
	LineStyle Style
}

// Render draws the bar on one row of b at r, and returns the number of rows it
// used, which is one or zero.
func (s Sparkbar) Render(b Buffer, r Rect) int {
	if r.Empty() {
		return 0
	}
	label := s.Label
	if label != "" {
		label += " "
	}
	// The value sits at the right-hand end; the line takes what is left.
	valueW := len([]rune(s.Current))
	if valueW > 0 {
		valueW++ // one space before it
	}
	lineW := r.W - len([]rune(label)) - valueW
	if lineW < 1 {
		// No room for a line: show the caption and the number, which is
		// the half of this that still carries information.
		b.DrawTextIn(r, r.X, r.Y, label+s.Current, s.Style)
		return 1
	}
	x := b.DrawText(r.X, r.Y, label, s.Style)
	var line string
	if s.Max > 0 {
		line = SparklineScaled(s.Values, lineW, 0, s.Max)
	} else {
		line = Sparkline(s.Values, lineW)
	}
	x = b.DrawText(x, r.Y, line, s.LineStyle)
	if s.Current != "" {
		b.DrawText(x+1, r.Y, s.Current, s.Style)
	}
	return 1
}
