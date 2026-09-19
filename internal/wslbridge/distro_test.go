package wslbridge

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
)

// These cover the wsl.exe output decoder and the two distro helpers that the
// broader tests in wslbridge_test.go exercise only indirectly. The decoder earns
// its own table because every string comparison hull makes about WSL depends on
// it: get it wrong and a registered engine distro reads as missing.

// withBOM prefixes a UTF-16LE byte-order mark.
func withBOM(b []byte) []byte {
	return append([]byte{0xFF, 0xFE}, b...)
}

func TestDecodeWSLOutput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "plain utf-8, what WSL_UTF8=1 produces",
			in:   []byte("hull-engine\nUbuntu\n"),
			want: "hull-engine\nUbuntu\n",
		},
		{
			name: "utf-8 with a byte-order mark",
			in:   append([]byte{0xEF, 0xBB, 0xBF}, "hull-engine\n"...),
			want: "hull-engine\n",
		},
		{
			name: "utf-16le with a byte-order mark, what an older wsl.exe writes",
			in:   withBOM(utf16leBytes("hull-engine\r\nUbuntu\r\n")),
			want: "hull-engine\r\nUbuntu\r\n",
		},
		{
			name: "utf-16le without a byte-order mark",
			in:   utf16leBytes("hull-engine\r\n"),
			want: "hull-engine\r\n",
		},
		{
			name: "utf-16be with a byte-order mark",
			in:   append([]byte{0xFE, 0xFF}, utf16beBytes("hull-engine\r\n")...),
			want: "hull-engine\r\n",
		},
		{
			name: "utf-16le carrying a non-ascii distro name",
			in:   withBOM(utf16leBytes("Ubuntu-22.04\r\nkübernetes\r\n")),
			want: "Ubuntu-22.04\r\nkübernetes\r\n",
		},
		{
			name: "utf-16le with an astral-plane name, so surrogate pairs are decoded",
			in:   withBOM(utf16leBytes("hull-🐳\r\n")),
			want: "hull-🐳\r\n",
		},
		{
			name: "an odd trailing byte is dropped rather than corrupting the string",
			in:   append(withBOM(utf16leBytes("abc")), 0x41),
			want: "abc",
		},
		{
			name: "empty input",
			in:   nil,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := DecodeWSLOutput(tt.in); got != tt.want {
				t.Fatalf("DecodeWSLOutput(% x) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestUTF16DecodeRoundTrip checks the decoder against the encoder for a spread
// of strings, including ones the heuristic could mistake for UTF-8.
func TestUTF16DecodeRoundTrip(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"hull-engine",
		"Ubuntu-24.04",
		"a",
		"docker-desktop-data\r\nhull-engine\r\n",
		"ÅÄÖ",
		strings.Repeat("hull-engine\r\n", 40),
	} {
		if got := DecodeWSLOutput(withBOM(utf16leBytes(s))); got != s {
			t.Errorf("round trip of %q gave %q", s, got)
		}
		if got := string(utf16Decode(utf16leBytes(s), littleEndianOrder())); got != s {
			t.Errorf("utf16Decode of %q gave %q", s, got)
		}
	}
}

// littleEndianOrder names the byte order utf16Decode is handed. wsl.exe writes
// UTF-16LE, so this is the only order the decoder ever sees in anger.
func littleEndianOrder() binary.ByteOrder { return binary.LittleEndian }

func TestListDistrosUsesTheQuietList(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{handler: func(string, []string) ([]byte, error) {
		return withBOM(utf16leBytes("hull-engine\r\nUbuntu\r\n")), nil
	}}
	names, err := ListDistros(context.Background(), Config{Runner: runner})
	if err != nil {
		t.Fatalf("ListDistros: %v", err)
	}
	if len(names) != 2 || names[0] != "hull-engine" || names[1] != "Ubuntu" {
		t.Fatalf("ListDistros = %q, want [hull-engine Ubuntu]", names)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	got := strings.Join(runner.calls[0], " ")
	if !strings.Contains(got, "--list") || !strings.Contains(got, "--quiet") {
		t.Fatalf("ran %q, want a --list --quiet invocation", got)
	}
}

func TestDistroRegisteredIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{handler: func(string, []string) ([]byte, error) {
		return []byte("hull-engine\nUbuntu\n"), nil
	}}
	for _, name := range []string{"hull-engine", "Hull-Engine", "HULL-ENGINE"} {
		ok, err := DistroRegistered(context.Background(), Config{Distro: name, Runner: runner})
		if err != nil {
			t.Fatalf("DistroRegistered(%q): %v", name, err)
		}
		if !ok {
			t.Errorf("DistroRegistered(%q) = false, want true: wsl.exe accepts either spelling", name)
		}
	}
	ok, err := DistroRegistered(context.Background(), Config{Distro: "nope", Runner: runner})
	if err != nil {
		t.Fatalf("DistroRegistered: %v", err)
	}
	if ok {
		t.Error("DistroRegistered(nope) = true, want false")
	}
}

// TestStartEngineWithSkipsBootWhenTheSocketIsThere keeps the common path cheap:
// every hull command would otherwise pay for a hull-boot round trip.
func TestStartEngineWithSkipsBootWhenTheSocketIsThere(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{handler: func(string, []string) ([]byte, error) { return nil, nil }}
	if err := StartEngineWith(context.Background(), Config{Runner: runner}); err != nil {
		t.Fatalf("StartEngineWith: %v", err)
	}
	if runner.count() != 1 {
		t.Fatalf("ran %d commands, want just the readiness check", runner.count())
	}
}

func TestEngineSocketReadyTestsForASocket(t *testing.T) {
	t.Parallel()
	var seen string
	runner := &fakeRunner{handler: func(_ string, args []string) ([]byte, error) {
		seen = strings.Join(args, " ")
		return nil, nil
	}}
	ready, err := EngineSocketReady(context.Background(), Config{Runner: runner})
	if err != nil {
		t.Fatalf("EngineSocketReady: %v", err)
	}
	if !ready {
		t.Fatal("EngineSocketReady = false, want true")
	}
	// "test -S", not "test -e": a regular file left by a crashed daemon is not
	// a socket, and dialling it fails in a way nobody can read.
	if !strings.Contains(seen, "test -S") {
		t.Fatalf("readiness check was %q, want a test -S", seen)
	}
	if !strings.Contains(seen, DefaultSocketPath) {
		t.Fatalf("readiness check %q does not name %s", seen, DefaultSocketPath)
	}
}

func TestWSLArgsSelectTheDistroAsRoot(t *testing.T) {
	t.Parallel()
	cfg := Config{Distro: "hull-engine"}.WithDefaults()
	got := strings.Join(cfg.wslArgs("/bin/sh", "-c", "true"), " ")
	// --exec matters: without it wsl.exe runs the command through a login
	// shell, which would rewrite the byte stream the relay depends on.
	want := "-d hull-engine -u root --exec /bin/sh -c true"
	if got != want {
		t.Fatalf("wslArgs = %q, want %q", got, want)
	}
}
