package tui

import "unicode/utf8"

// KeyType names a key that is not a printable character.
type KeyType int

// The keys the dashboard understands. Anything else arrives as [KeyRune] and
// is either a command letter or filter text.
const (
	// KeyRune is a printable character, carried in Key.Rune.
	KeyRune KeyType = iota
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyEnter
	KeyEscape
	KeyTab
	KeyBackTab
	KeyBackspace
	KeyDelete
	KeyHome
	KeyEnd
	KeyPageUp
	KeyPageDown
	KeyCtrlC
	KeyCtrlD
	KeyCtrlL
	KeyCtrlU
	// KeyUnknown is a recognised but unmapped escape sequence, which is
	// swallowed rather than treated as text.
	KeyUnknown
)

// Key is one decoded keystroke.
type Key struct {
	// Type is the key, or [KeyRune] for a printable character.
	Type KeyType
	// Rune is the character when Type is [KeyRune].
	Rune rune
}

// RuneKey is a shorthand for a printable key, used by tests and by the help
// text.
func RuneKey(r rune) Key { return Key{Type: KeyRune, Rune: r} }

// DecodeKey decodes the first keystroke in p.
//
// It returns the key, how many bytes it consumed, and whether a key was
// decoded at all. A false third result means p ends in the middle of an escape
// sequence or a UTF-8 rune: the caller should read more bytes and try again
// with the longer buffer. A lone ESC byte is decoded as [KeyEscape] rather
// than held, because terminals deliver a complete sequence in a single write
// and waiting would make the escape key feel broken.
func DecodeKey(p []byte) (Key, int, bool) {
	if len(p) == 0 {
		return Key{}, 0, false
	}
	switch p[0] {
	case 0x1b:
		return decodeEscape(p)
	case '\r', '\n':
		return Key{Type: KeyEnter}, 1, true
	case '\t':
		return Key{Type: KeyTab}, 1, true
	case 0x7f, 0x08:
		return Key{Type: KeyBackspace}, 1, true
	case 0x03:
		return Key{Type: KeyCtrlC}, 1, true
	case 0x04:
		return Key{Type: KeyCtrlD}, 1, true
	case 0x0c:
		return Key{Type: KeyCtrlL}, 1, true
	case 0x15:
		return Key{Type: KeyCtrlU}, 1, true
	}
	if p[0] < 0x20 {
		return Key{Type: KeyUnknown}, 1, true
	}
	if p[0] < utf8.RuneSelf {
		return Key{Type: KeyRune, Rune: rune(p[0])}, 1, true
	}
	r, size := utf8.DecodeRune(p)
	if r == utf8.RuneError && size <= 1 {
		if !utf8.FullRune(p) {
			return Key{}, 0, false
		}
		return Key{Type: KeyUnknown}, 1, true
	}
	return Key{Type: KeyRune, Rune: r}, size, true
}

// decodeEscape handles ESC-introduced sequences: CSI (ESC [), SS3 (ESC O) and
// a bare ESC.
func decodeEscape(p []byte) (Key, int, bool) {
	if len(p) == 1 {
		return Key{Type: KeyEscape}, 1, true
	}
	switch p[1] {
	case '[':
		return decodeCSI(p)
	case 'O':
		if len(p) < 3 {
			return Key{}, 0, false
		}
		if k, ok := ss3Key(p[2]); ok {
			return k, 3, true
		}
		return Key{Type: KeyUnknown}, 3, true
	}
	// ESC followed by anything else: alt-<key>, which the dashboard does
	// not bind. Swallow both bytes so the letter does not leak through as a
	// command.
	return Key{Type: KeyUnknown}, 2, true
}

// decodeCSI parses ESC [ <params> <final> and maps the final byte.
func decodeCSI(p []byte) (Key, int, bool) {
	i := 2
	start := i
	for i < len(p) && (p[i] >= 0x30 && p[i] <= 0x3f) {
		i++
	}
	for i < len(p) && (p[i] >= 0x20 && p[i] <= 0x2f) {
		i++
	}
	if i >= len(p) {
		return Key{}, 0, false
	}
	final := p[i]
	params := string(p[start:i])
	n := i + 1
	if k, ok := csiKey(final, params); ok {
		return k, n, true
	}
	return Key{Type: KeyUnknown}, n, true
}

// csiKey maps a CSI final byte, with its parameters, onto a key.
func csiKey(final byte, params string) (Key, bool) {
	switch final {
	case 'A':
		return Key{Type: KeyUp}, true
	case 'B':
		return Key{Type: KeyDown}, true
	case 'C':
		return Key{Type: KeyRight}, true
	case 'D':
		return Key{Type: KeyLeft}, true
	case 'H':
		return Key{Type: KeyHome}, true
	case 'F':
		return Key{Type: KeyEnd}, true
	case 'Z':
		return Key{Type: KeyBackTab}, true
	case '~':
		switch leadingNumber(params) {
		case 1, 7:
			return Key{Type: KeyHome}, true
		case 3:
			return Key{Type: KeyDelete}, true
		case 4, 8:
			return Key{Type: KeyEnd}, true
		case 5:
			return Key{Type: KeyPageUp}, true
		case 6:
			return Key{Type: KeyPageDown}, true
		}
	}
	return Key{}, false
}

// ss3Key maps the SS3 sequences the arrow keys use in application mode.
func ss3Key(final byte) (Key, bool) {
	switch final {
	case 'A':
		return Key{Type: KeyUp}, true
	case 'B':
		return Key{Type: KeyDown}, true
	case 'C':
		return Key{Type: KeyRight}, true
	case 'D':
		return Key{Type: KeyLeft}, true
	case 'H':
		return Key{Type: KeyHome}, true
	case 'F':
		return Key{Type: KeyEnd}, true
	}
	return Key{}, false
}

// leadingNumber returns the first numeric parameter of a CSI sequence, or 0.
func leadingNumber(params string) int {
	n := 0
	seen := false
	for _, c := range params {
		if c < '0' || c > '9' {
			break
		}
		seen = true
		n = n*10 + int(c-'0')
	}
	if !seen {
		return 0
	}
	return n
}

// Mode is which input mode the dashboard is in. The key map depends on it:
// "d" deletes a container in [ModeNormal] and types a letter in [ModeFilter],
// and that distinction is the whole reason [Dispatch] takes a mode.
type Mode int

// The input modes.
const (
	// ModeNormal is the dashboard proper.
	ModeNormal Mode = iota
	// ModeFilter is the filter prompt: most keys are text.
	ModeFilter
	// ModeConfirm is a yes/no question, which swallows everything else so
	// a stray keystroke cannot delete a container.
	ModeConfirm
	// ModeHelp is the help overlay, dismissed by any key.
	ModeHelp
)

// Action is what a keystroke means once the mode is taken into account.
type Action int

// The actions the key map produces. They are deliberately about intent rather
// than about keys, so the same action can be reached from more than one key
// and the dispatcher stays a pure function.
const (
	// ActionNone means the key is not bound in this mode.
	ActionNone Action = iota
	ActionQuit
	ActionSelectUp
	ActionSelectDown
	ActionSelectTop
	ActionSelectBottom
	ActionNextTab
	ActionPrevTab
	// ActionSelectTab jumps to the tab named by the key, which is one of
	// "1".."4" or "l" for the logs tab.
	ActionSelectTab
	ActionScrollUp
	ActionScrollDown
	ActionPageUp
	ActionPageDown
	ActionFilterBegin
	ActionFilterInput
	ActionFilterBackspace
	ActionFilterClear
	ActionFilterAccept
	ActionFilterCancel
	ActionStop
	ActionStart
	ActionRestart
	ActionPause
	ActionDelete
	ActionExec
	ActionHelp
	ActionWarnings
	ActionConfirmYes
	ActionConfirmNo
	ActionDismiss
	ActionRedraw
)

// Dispatch maps a keystroke in a given mode onto an action. It is a pure
// function with no state, which is what makes the whole key map testable as a
// table.
func Dispatch(mode Mode, k Key) Action {
	if k.Type == KeyCtrlC {
		return ActionQuit
	}
	switch mode {
	case ModeHelp:
		if k.Type == KeyCtrlL {
			return ActionRedraw
		}
		return ActionDismiss
	case ModeConfirm:
		switch {
		case k.Type == KeyEnter, k.Type == KeyRune && (k.Rune == 'y' || k.Rune == 'Y'):
			return ActionConfirmYes
		case k.Type == KeyEscape, k.Type == KeyRune && (k.Rune == 'n' || k.Rune == 'N' || k.Rune == 'q'):
			return ActionConfirmNo
		}
		return ActionNone
	case ModeFilter:
		switch k.Type {
		case KeyEnter:
			return ActionFilterAccept
		case KeyEscape:
			return ActionFilterCancel
		case KeyBackspace:
			return ActionFilterBackspace
		case KeyCtrlU:
			return ActionFilterClear
		case KeyUp:
			return ActionSelectUp
		case KeyDown:
			return ActionSelectDown
		case KeyPageUp:
			return ActionPageUp
		case KeyPageDown:
			return ActionPageDown
		case KeyRune:
			return ActionFilterInput
		}
		return ActionNone
	}
	return dispatchNormal(k)
}

// dispatchNormal is the key map of the dashboard proper.
func dispatchNormal(k Key) Action {
	switch k.Type {
	case KeyUp:
		return ActionSelectUp
	case KeyDown:
		return ActionSelectDown
	case KeyHome:
		return ActionSelectTop
	case KeyEnd:
		return ActionSelectBottom
	case KeyTab:
		return ActionNextTab
	case KeyBackTab:
		return ActionPrevTab
	case KeyPageUp:
		return ActionPageUp
	case KeyPageDown:
		return ActionPageDown
	case KeyCtrlL:
		return ActionRedraw
	case KeyCtrlD:
		return ActionQuit
	case KeyEscape:
		return ActionDismiss
	case KeyRune:
		return dispatchRune(k.Rune)
	}
	return ActionNone
}

// dispatchRune is the letter half of the normal key map.
func dispatchRune(r rune) Action {
	switch r {
	case 'q':
		return ActionQuit
	case 'j':
		return ActionSelectDown
	case 'k':
		return ActionSelectUp
	case 'g':
		return ActionSelectTop
	case 'G':
		return ActionSelectBottom
	case '/':
		return ActionFilterBegin
	case 's':
		return ActionStop
	case 'S':
		return ActionStart
	case 'r':
		return ActionRestart
	case 'p':
		return ActionPause
	case 'd':
		return ActionDelete
	case 'e':
		return ActionExec
	case 'l':
		return ActionSelectTab
	case 'w':
		return ActionWarnings
	case '?', 'h':
		return ActionHelp
	case '1', '2', '3', '4':
		return ActionSelectTab
	case '[':
		return ActionPrevTab
	case ']':
		return ActionNextTab
	case 'u':
		return ActionScrollUp
	case 'n':
		return ActionScrollDown
	}
	return ActionNone
}

// tabForKey maps the keys that jump straight to a tab onto that tab, and
// reports whether the key named one at all.
func tabForKey(k Key) (DetailTab, bool) {
	if k.Type != KeyRune {
		return 0, false
	}
	switch k.Rune {
	case 'l':
		return TabLogs, true
	case '1':
		return TabLogs, true
	case '2':
		return TabStats, true
	case '3':
		return TabInspect, true
	case '4':
		return TabPorts, true
	}
	return 0, false
}
