package tui

import "strings"

// Tabs is the one-row tab bar at the top of the detail pane.
//
// It degrades in two steps rather than one: when the full bar does not fit it
// drops the separators and pads less, and when even that does not fit it shows
// only the active tab with a "2/4" counter, so the user always knows where
// they are in the cycle even on a forty-column pane.
type Tabs struct {
	// Titles are the tab names, left to right.
	Titles []string
	// Active is the index of the selected tab.
	Active int
	// Style paints an inactive tab, ActiveStyle the selected one, and
	// SuffixStyle the trailing text a pane may add on the right.
	Style       Style
	ActiveStyle Style
	SuffixStyle Style
	// Suffix is optional right-aligned text, such as the selected
	// container's name.
	Suffix string
}

// tabSeparator sits between tabs when there is room for it. The labels carry
// their own padding, so the separator is the bare rule.
const tabSeparator = "│"

// Render draws the tab bar into b at r.
func (t Tabs) Render(b Buffer, r Rect) {
	if r.Empty() || len(t.Titles) == 0 {
		return
	}
	active := clampInt(t.Active, 0, len(t.Titles)-1)
	b.Fill(r, Cell{Rune: ' ', Style: t.Style})

	full := 0
	for i, title := range t.Titles {
		full += len([]rune(title)) + 2
		if i > 0 {
			full += len([]rune(tabSeparator))
		}
	}
	suffixW := 0
	if t.Suffix != "" {
		suffixW = len([]rune(t.Suffix)) + 1
	}

	if full+suffixW > r.W {
		// Not enough room for every tab: show the active one alone.
		label := " " + t.Titles[active] + " "
		counter := " " + itoa(active+1) + "/" + itoa(len(t.Titles))
		x := b.DrawTextIn(r, r.X, r.Y, label, t.ActiveStyle)
		b.DrawTextIn(r, x, r.Y, counter, t.Style)
		return
	}

	x := r.X
	for i, title := range t.Titles {
		if i > 0 {
			x = b.DrawTextIn(r, x, r.Y, tabSeparator, t.Style)
		}
		style := t.Style
		if i == active {
			style = t.ActiveStyle
		}
		x = b.DrawTextIn(r, x, r.Y, " "+title+" ", style)
	}
	if t.Suffix != "" {
		start := r.Right() - len([]rune(t.Suffix))
		if start > x {
			b.DrawTextIn(r, start, r.Y, t.Suffix, t.SuffixStyle)
		}
	}
}

// itoa is strconv.Itoa without the import, kept local because the tab bar is
// the only place in this file that needs it.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// PaneTitle draws a pane heading: a bold caption, then a rule of box-drawing
// characters to the right edge, with optional right-aligned detail. It is what
// gives the four panes their separation without spending a cell on borders.
func PaneTitle(b Buffer, r Rect, title, right string, style, ruleStyle Style) {
	if r.Empty() {
		return
	}
	x := b.DrawTextIn(r, r.X, r.Y, title, style)
	rightW := 0
	if right != "" {
		rightW = len([]rune(right)) + 1
	}
	ruleEnd := r.Right() - rightW
	if ruleEnd > x+1 {
		b.DrawText(x, r.Y, " "+strings.Repeat("─", ruleEnd-x-1), ruleStyle)
	}
	if right != "" && ruleEnd >= r.X {
		b.DrawTextIn(r, r.Right()-len([]rune(right)), r.Y, right, ruleStyle)
	}
}
