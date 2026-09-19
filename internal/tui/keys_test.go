package tui

import "testing"

func TestDecodeKey(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		want     Key
		consumed int
		ok       bool
	}{
		{"plain letter", "j", RuneKey('j'), 1, true},
		{"capital letter", "S", RuneKey('S'), 1, true},
		{"slash", "/", RuneKey('/'), 1, true},
		{"enter", "\r", Key{Type: KeyEnter}, 1, true},
		{"newline is enter too", "\n", Key{Type: KeyEnter}, 1, true},
		{"tab", "\t", Key{Type: KeyTab}, 1, true},
		{"backspace", "\x7f", Key{Type: KeyBackspace}, 1, true},
		{"ctrl-c", "\x03", Key{Type: KeyCtrlC}, 1, true},
		{"ctrl-u", "\x15", Key{Type: KeyCtrlU}, 1, true},
		{"up arrow", "\x1b[A", Key{Type: KeyUp}, 3, true},
		{"down arrow", "\x1b[B", Key{Type: KeyDown}, 3, true},
		{"application-mode up", "\x1bOA", Key{Type: KeyUp}, 3, true},
		{"shift-tab", "\x1b[Z", Key{Type: KeyBackTab}, 3, true},
		{"page up", "\x1b[5~", Key{Type: KeyPageUp}, 4, true},
		{"page down", "\x1b[6~", Key{Type: KeyPageDown}, 4, true},
		{"home", "\x1b[H", Key{Type: KeyHome}, 3, true},
		{"end", "\x1b[4~", Key{Type: KeyEnd}, 4, true},
		{"delete", "\x1b[3~", Key{Type: KeyDelete}, 4, true},
		{"modified arrow still moves", "\x1b[1;5A", Key{Type: KeyUp}, 6, true},
		{"lone escape", "\x1b", Key{Type: KeyEscape}, 1, true},
		{"multi-byte rune", "é", RuneKey('é'), 2, true},
		{"unknown csi is swallowed", "\x1b[200~", Key{Type: KeyUnknown}, 6, true},
		{"empty", "", Key{}, 0, false},
		{"truncated csi needs more bytes", "\x1b[", Key{}, 0, false},
		{"truncated parameters need more bytes", "\x1b[1;", Key{}, 0, false},
		{"truncated ss3 needs more bytes", "\x1bO", Key{}, 0, false},
		{"truncated rune needs more bytes", "\xc3", Key{}, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, n, ok := DecodeKey([]byte(tc.in))
			if ok != tc.ok {
				t.Fatalf("DecodeKey(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			}
			if !ok {
				return
			}
			if got != tc.want {
				t.Errorf("DecodeKey(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
			if n != tc.consumed {
				t.Errorf("DecodeKey(%q) consumed %d, want %d", tc.in, n, tc.consumed)
			}
		})
	}
}

func TestDecodeKeySequenceOfKeys(t *testing.T) {
	// A single read can carry several keystrokes; the decoder must walk
	// them without losing the boundary between an escape sequence and the
	// letter after it.
	in := []byte("j\x1b[Bk\x1b[6~q")
	want := []Key{
		RuneKey('j'),
		{Type: KeyDown},
		RuneKey('k'),
		{Type: KeyPageDown},
		RuneKey('q'),
	}
	var got []Key
	for len(in) > 0 {
		k, n, ok := DecodeKey(in)
		if !ok {
			t.Fatalf("incomplete sequence at %q", in)
		}
		in = in[n:]
		got = append(got, k)
	}
	if len(got) != len(want) {
		t.Fatalf("decoded %d keys, want %d (%+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDispatch(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
		key  Key
		want Action
	}{
		// Normal mode.
		{"j selects down", ModeNormal, RuneKey('j'), ActionSelectDown},
		{"k selects up", ModeNormal, RuneKey('k'), ActionSelectUp},
		{"down arrow selects down", ModeNormal, Key{Type: KeyDown}, ActionSelectDown},
		{"up arrow selects up", ModeNormal, Key{Type: KeyUp}, ActionSelectUp},
		{"tab cycles forward", ModeNormal, Key{Type: KeyTab}, ActionNextTab},
		{"shift-tab cycles back", ModeNormal, Key{Type: KeyBackTab}, ActionPrevTab},
		{"slash filters", ModeNormal, RuneKey('/'), ActionFilterBegin},
		{"s stops", ModeNormal, RuneKey('s'), ActionStop},
		{"S starts", ModeNormal, RuneKey('S'), ActionStart},
		{"r restarts", ModeNormal, RuneKey('r'), ActionRestart},
		{"d deletes", ModeNormal, RuneKey('d'), ActionDelete},
		{"l jumps to logs", ModeNormal, RuneKey('l'), ActionSelectTab},
		{"2 jumps to stats", ModeNormal, RuneKey('2'), ActionSelectTab},
		{"e opens a shell", ModeNormal, RuneKey('e'), ActionExec},
		{"p pauses", ModeNormal, RuneKey('p'), ActionPause},
		{"question mark helps", ModeNormal, RuneKey('?'), ActionHelp},
		{"w shows warnings", ModeNormal, RuneKey('w'), ActionWarnings},
		{"q quits", ModeNormal, RuneKey('q'), ActionQuit},
		{"ctrl-c quits", ModeNormal, Key{Type: KeyCtrlC}, ActionQuit},
		{"unbound letter does nothing", ModeNormal, RuneKey('z'), ActionNone},

		// Filter mode: letters are text, not commands.
		{"d types instead of deleting", ModeFilter, RuneKey('d'), ActionFilterInput},
		{"q types instead of quitting", ModeFilter, RuneKey('q'), ActionFilterInput},
		{"enter accepts", ModeFilter, Key{Type: KeyEnter}, ActionFilterAccept},
		{"escape cancels", ModeFilter, Key{Type: KeyEscape}, ActionFilterCancel},
		{"backspace deletes a character", ModeFilter, Key{Type: KeyBackspace}, ActionFilterBackspace},
		{"ctrl-u clears", ModeFilter, Key{Type: KeyCtrlU}, ActionFilterClear},
		{"arrows still select", ModeFilter, Key{Type: KeyDown}, ActionSelectDown},
		{"ctrl-c still quits", ModeFilter, Key{Type: KeyCtrlC}, ActionQuit},

		// Confirm mode swallows everything but the answer.
		{"y confirms", ModeConfirm, RuneKey('y'), ActionConfirmYes},
		{"enter confirms", ModeConfirm, Key{Type: KeyEnter}, ActionConfirmYes},
		{"n declines", ModeConfirm, RuneKey('n'), ActionConfirmNo},
		{"escape declines", ModeConfirm, Key{Type: KeyEscape}, ActionConfirmNo},
		{"a stray letter does nothing", ModeConfirm, RuneKey('j'), ActionNone},
		{"ctrl-c still quits", ModeConfirm, Key{Type: KeyCtrlC}, ActionQuit},

		// Help mode: anything closes it.
		{"any key dismisses", ModeHelp, RuneKey('x'), ActionDismiss},
		{"escape dismisses", ModeHelp, Key{Type: KeyEscape}, ActionDismiss},
		{"ctrl-c still quits", ModeHelp, Key{Type: KeyCtrlC}, ActionQuit},
	}

	for _, tc := range tests {
		t.Run(tc.name+"/"+modeName(tc.mode), func(t *testing.T) {
			if got := Dispatch(tc.mode, tc.key); got != tc.want {
				t.Errorf("Dispatch(%v, %+v) = %v, want %v", tc.mode, tc.key, got, tc.want)
			}
		})
	}
}

func TestTabForKey(t *testing.T) {
	tests := []struct {
		key  Key
		want DetailTab
		ok   bool
	}{
		{RuneKey('l'), TabLogs, true},
		{RuneKey('1'), TabLogs, true},
		{RuneKey('2'), TabStats, true},
		{RuneKey('3'), TabInspect, true},
		{RuneKey('4'), TabPorts, true},
		{RuneKey('5'), 0, false},
		{Key{Type: KeyTab}, 0, false},
	}
	for _, tc := range tests {
		got, ok := tabForKey(tc.key)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("tabForKey(%+v) = %v, %v; want %v, %v", tc.key, got, ok, tc.want, tc.ok)
		}
	}
}

// modeName names a mode for a subtest.
func modeName(m Mode) string {
	switch m {
	case ModeFilter:
		return "filter"
	case ModeConfirm:
		return "confirm"
	case ModeHelp:
		return "help"
	default:
		return "normal"
	}
}
