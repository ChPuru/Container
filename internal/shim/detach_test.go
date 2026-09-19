package shim

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseDetachKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		spec    string
		want    []byte
		wantErr string
	}{
		{name: "empty means the default", spec: "", want: []byte{0x10, 0x11}},
		{name: "docker default", spec: "ctrl-p,ctrl-q", want: []byte{0x10, 0x11}},
		{name: "uppercase ctrl letter", spec: "ctrl-P,ctrl-Q", want: []byte{0x10, 0x11}},
		{name: "single key", spec: "ctrl-d", want: []byte{0x04}},
		{name: "plain characters", spec: "a,b,c", want: []byte{'a', 'b', 'c'}},
		{name: "ctrl-@ is NUL", spec: "ctrl-@", want: []byte{0x00}},
		{name: "ctrl-[ is ESC", spec: "ctrl-[", want: []byte{0x1b}},
		{name: "ctrl-? is DEL", spec: "ctrl-?", want: []byte{0x7f}},
		{name: "ctrl-_ is 31", spec: "ctrl-_", want: []byte{0x1f}},
		{name: "mixed", spec: "ctrl-a,z,ctrl-]", want: []byte{0x01, 'z', 0x1d}},

		{name: "multi-character key", spec: "abc", wantErr: "single character"},
		{name: "ctrl with two characters", spec: "ctrl-ab", wantErr: "exactly one character"},
		{name: "ctrl of a non-control character", spec: "ctrl-1", wantErr: "not a control character"},
		{name: "empty element", spec: "ctrl-p,,ctrl-q", wantErr: "empty key"},
		{name: "too many keys", spec: strings.TrimSuffix(strings.Repeat("a,", 20), ","), wantErr: "at most"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseDetachKeys(tt.spec)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseDetachKeys(%q) = %v, want an error containing %q", tt.spec, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDetachKeys(%q): %v", tt.spec, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("ParseDetachKeys(%q) = % x, want % x", tt.spec, got, tt.want)
			}
		})
	}
}

// TestDetachFilter drives the state machine one write at a time. The
// load-bearing case is a prefix of the sequence followed by an unrelated byte:
// both must reach the container, because the user meant to type them.
func TestDetachFilter(t *testing.T) {
	t.Parallel()
	const (
		ctrlP = 0x10
		ctrlQ = 0x11
	)
	tests := []struct {
		name     string
		keys     []byte
		writes   []string
		wantOut  string
		wantStop int // index of the write that detaches, -1 for none
	}{
		{
			name:     "no keys is a pass-through",
			keys:     nil,
			writes:   []string{string([]byte{ctrlP, ctrlQ}), "hello"},
			wantOut:  string([]byte{ctrlP, ctrlQ}) + "hello",
			wantStop: -1,
		},
		{
			name:     "plain text flows straight through",
			keys:     []byte{ctrlP, ctrlQ},
			writes:   []string{"ls -l\n", "echo hi\n"},
			wantOut:  "ls -l\necho hi\n",
			wantStop: -1,
		},
		{
			name:     "the full sequence in one write detaches",
			keys:     []byte{ctrlP, ctrlQ},
			writes:   []string{string([]byte{ctrlP, ctrlQ})},
			wantOut:  "",
			wantStop: 0,
		},
		{
			name:     "the sequence split across writes still detaches",
			keys:     []byte{ctrlP, ctrlQ},
			writes:   []string{string([]byte{ctrlP}), string([]byte{ctrlQ})},
			wantOut:  "",
			wantStop: 1,
		},
		{
			name:     "a prefix followed by an unrelated byte is forwarded whole",
			keys:     []byte{ctrlP, ctrlQ},
			writes:   []string{string([]byte{ctrlP, 'x'})},
			wantOut:  string([]byte{ctrlP, 'x'}),
			wantStop: -1,
		},
		{
			name:     "a prefix in one write and an unrelated byte in the next",
			keys:     []byte{ctrlP, ctrlQ},
			writes:   []string{string([]byte{ctrlP}), "x"},
			wantOut:  string([]byte{ctrlP, 'x'}),
			wantStop: -1,
		},
		{
			name:     "text around a completed sequence",
			keys:     []byte{ctrlP, ctrlQ},
			writes:   []string{"before" + string([]byte{ctrlP, ctrlQ}) + "after"},
			wantOut:  "before",
			wantStop: 0,
		},
		{
			name:     "a repeated first key still matches on the second try",
			keys:     []byte{ctrlP, ctrlQ},
			writes:   []string{string([]byte{ctrlP, ctrlP, ctrlQ})},
			wantOut:  string([]byte{ctrlP}),
			wantStop: 0,
		},
		{
			name:     "an overlapping prefix backtracks rather than restarting",
			keys:     []byte("aab"),
			writes:   []string{"aaab"},
			wantOut:  "a",
			wantStop: 0,
		},
		{
			name:     "a near miss of an overlapping sequence forwards everything",
			keys:     []byte("aab"),
			writes:   []string{"aac"},
			wantOut:  "aac",
			wantStop: -1,
		},
		{
			name:     "a three-key sequence one byte at a time",
			keys:     []byte{ctrlP, ctrlP, ctrlQ},
			writes:   []string{string([]byte{ctrlP}), string([]byte{ctrlP}), string([]byte{ctrlQ})},
			wantOut:  "",
			wantStop: 2,
		},
		{
			name:     "a three-key sequence broken at the last byte",
			keys:     []byte{ctrlP, ctrlP, ctrlQ},
			writes:   []string{string([]byte{ctrlP, ctrlP}), "z"},
			wantOut:  string([]byte{ctrlP, ctrlP, 'z'}),
			wantStop: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := newDetachFilter(tt.keys)
			var out bytes.Buffer
			stopped := -1
			for i, w := range tt.writes {
				got, detached := d.Filter([]byte(w))
				out.Write(got)
				if detached {
					stopped = i
					break
				}
			}
			if stopped != tt.wantStop {
				t.Errorf("detached at write %d, want %d", stopped, tt.wantStop)
			}
			if out.String() != tt.wantOut {
				t.Errorf("forwarded % x, want % x", out.Bytes(), tt.wantOut)
			}
		})
	}
}

func TestDetachFilterFlushReleasesAPartialPrefix(t *testing.T) {
	t.Parallel()
	keys, err := ParseDetachKeys(DefaultDetachKeys)
	if err != nil {
		t.Fatalf("ParseDetachKeys: %v", err)
	}
	d := newDetachFilter(keys)

	out, detached := d.Filter([]byte{0x10})
	if detached || len(out) != 0 {
		t.Fatalf("a lone ctrl-p should be withheld, got % x detached=%v", out, detached)
	}
	if d.Pending() != 1 {
		t.Fatalf("Pending = %d, want 1", d.Pending())
	}
	rest := d.Flush()
	if !bytes.Equal(rest, []byte{0x10}) {
		t.Fatalf("Flush = % x, want 10", rest)
	}
	if d.Pending() != 0 {
		t.Fatalf("Pending after Flush = %d, want 0", d.Pending())
	}
	if got := d.Flush(); got != nil {
		t.Fatalf("a second Flush returned % x, want nil", got)
	}
}

func TestDetachFilterIsReusableAfterDetaching(t *testing.T) {
	t.Parallel()
	d := newDetachFilter([]byte{0x10, 0x11})
	if _, detached := d.Filter([]byte{0x10, 0x11}); !detached {
		t.Fatal("expected to detach")
	}
	// The buffer must be empty again, so a reused filter does not carry a
	// phantom prefix into the next session.
	if d.Pending() != 0 {
		t.Fatalf("Pending = %d, want 0", d.Pending())
	}
	out, detached := d.Filter([]byte("hi"))
	if detached || string(out) != "hi" {
		t.Fatalf("after detaching, Filter(%q) = %q detached=%v", "hi", out, detached)
	}
}
