package wslbridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// wsl.exe writes UTF-16LE to a pipe unless WSL_UTF8=1 is set, and the variable
// only arrived in WSL 0.64.0. Every helper here sets it and then decodes
// defensively anyway: an older wsl.exe, a policy-managed environment that strips
// the variable, or a Store update that regresses it would otherwise turn "wsl -l
// -q" into a list of names nothing matches, and hull would report the engine
// distro missing on a machine where it is installed.

// DecodeWSLOutput converts wsl.exe output to a UTF-8 string, transparently
// handling UTF-16LE (with or without a byte-order mark), UTF-16BE and UTF-8.
func DecodeWSLOutput(b []byte) string {
	return string(decodeWSLBytes(b))
}

// decodeWSLBytes is DecodeWSLOutput without the string conversion.
func decodeWSLBytes(b []byte) []byte {
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		return utf16Decode(b[2:], binary.LittleEndian)
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		return utf16Decode(b[2:], binary.BigEndian)
	case looksUTF16LE(b):
		return utf16Decode(b, binary.LittleEndian)
	default:
		return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	}
}

// looksUTF16LE guesses at BOM-less UTF-16LE. Text wsl.exe emits is dominated by
// ASCII (distro names, "Windows Subsystem for Linux"), so in UTF-16LE most high
// bytes are zero, and in any UTF-8 encoding of the same text none are.
func looksUTF16LE(b []byte) bool {
	if len(b) < 2 || len(b)%2 != 0 {
		return false
	}
	sample := len(b)
	if sample > 256 {
		sample = 256
	}
	pairs, zeroHigh := 0, 0
	for i := 0; i+1 < sample; i += 2 {
		pairs++
		if b[i+1] == 0x00 {
			zeroHigh++
		}
	}
	return pairs > 0 && zeroHigh*2 > pairs
}

// utf16Decode decodes UTF-16 code units in the given byte order, including
// surrogate pairs. A trailing odd byte is dropped rather than corrupting the
// whole string.
func utf16Decode(b []byte, order binary.ByteOrder) []byte {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = order.Uint16(b[2*i:])
	}
	return []byte(string(utf16.Decode(units)))
}

// ParseDistroList turns the output of "wsl --list --quiet" into distro names.
// It tolerates UTF-16LE output, CRLF line endings, a byte-order mark on the
// first name, stray NULs from a truncated UTF-16 read, and the "(Default)"
// marker that appears when --quiet was not honoured.
func ParseDistroList(out []byte) []string {
	text := DecodeWSLOutput(out)
	var names []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\x00", ""))
		line = strings.TrimPrefix(line, "\ufeff")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.Index(line, " (Default)"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		names = append(names, line)
	}
	return names
}

// wslArgs prefixes the distro selection every engine-side command needs.
func (c Config) wslArgs(args ...string) []string {
	return append([]string{"-d", c.Distro, "-u", "root", "--exec"}, args...)
}

// ListDistros returns the distros registered with WSL, in wsl.exe's own order.
func ListDistros(ctx context.Context, cfg Config) ([]string, error) {
	cfg = cfg.WithDefaults()
	out, err := cfg.Runner.Run(ctx, cfg.WSLPath, "--list", "--quiet")
	if err != nil {
		return nil, fmt.Errorf("wslbridge: list distros: %w", err)
	}
	return ParseDistroList(out), nil
}

// DistroRegistered reports whether a distro of the given name is registered.
// The comparison is case-insensitive, because wsl.exe accepts "Ubuntu" for a
// distro registered as "ubuntu".
func DistroRegistered(ctx context.Context, cfg Config) (bool, error) {
	cfg = cfg.WithDefaults()
	names, err := ListDistros(ctx, cfg)
	if err != nil {
		return false, err
	}
	for _, name := range names {
		if strings.EqualFold(name, cfg.Distro) {
			return true, nil
		}
	}
	return false, nil
}

// EnsureDistro checks that the engine distro is registered with WSL, and
// returns an error naming the installer when it is not.
func EnsureDistro(ctx context.Context, distro string) error {
	return EnsureDistroWith(ctx, Config{Distro: distro})
}

// EnsureDistroWith is EnsureDistro with a full configuration, so tests and the
// CLI can supply their own runner and wsl.exe path.
func EnsureDistroWith(ctx context.Context, cfg Config) error {
	cfg = cfg.WithDefaults()
	names, err := ListDistros(ctx, cfg)
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.EqualFold(name, cfg.Distro) {
			return nil
		}
	}
	listed := "none"
	if len(names) > 0 {
		listed = strings.Join(names, ", ")
	}
	return fmt.Errorf("wslbridge: %q is not registered with WSL (registered: %s). "+
		"Install the engine with: powershell -ExecutionPolicy Bypass -File scripts\\install.ps1: %w",
		cfg.Distro, listed, ErrDistroMissing)
}

// EngineSocketReady reports whether hulld's API socket exists inside the distro.
// A false return with a nil error means the engine is not up yet; an error means
// the distro itself could not be reached.
func EngineSocketReady(ctx context.Context, cfg Config) (bool, error) {
	cfg = cfg.WithDefaults()
	// "test -S" rather than a bare existence check: a plain file left behind by
	// a crashed daemon is not a socket, and dialling it would fail confusingly.
	args := cfg.wslArgs("/bin/sh", "-c", "test -S "+shellQuote(cfg.SocketPath))
	if _, err := cfg.Runner.Run(ctx, cfg.WSLPath, args...); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		// A non-zero exit is the normal "not there yet" answer, and wsl.exe
		// reports a missing distro the same way, so the caller learns the
		// difference from EnsureDistro rather than from here.
		return false, nil
	}
	return true, nil
}

// StartEngine boots hulld inside the distro and waits for its API socket to
// appear. It is safe to call when the engine is already running: hull-boot's
// supervisor loop is idempotent, and the socket check short-circuits.
func StartEngine(ctx context.Context, distro string) error {
	return StartEngineWith(ctx, Config{Distro: distro})
}

// StartEngineWith is StartEngine with a full configuration.
func StartEngineWith(ctx context.Context, cfg Config) error {
	cfg = cfg.WithDefaults()
	if ready, err := EngineSocketReady(ctx, cfg); err != nil {
		return err
	} else if ready {
		return nil
	}

	// hull-boot backgrounds hulld and returns; the redirection keeps wsl.exe
	// from holding the pipe open and blocking here forever.
	boot := shellQuote(BootBinary) + " >>/var/log/hull-boot.log 2>&1 &"
	args := cfg.wslArgs("/bin/sh", "-c", boot)
	if _, err := cfg.Runner.Run(ctx, cfg.WSLPath, args...); err != nil {
		return fmt.Errorf("wslbridge: start engine in %q: %w", cfg.Distro, err)
	}

	deadline := time.Now().Add(cfg.EngineStartTimeout)
	delay := 100 * time.Millisecond
	for {
		ready, err := EngineSocketReady(ctx, cfg)
		if err != nil {
			return err
		}
		if ready {
			cfg.Logger.Debug("wslbridge: engine socket is up", "distro", cfg.Distro, "socket", cfg.SocketPath)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wslbridge: engine socket %s did not appear in %q within %s; see /var/log/hull-boot.log inside the distro",
				cfg.SocketPath, cfg.Distro, cfg.EngineStartTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < time.Second {
			delay *= 2
		}
	}
}

// shellQuote wraps s for /bin/sh. Paths here come from configuration rather than
// from a container, but they still reach a shell, so they are quoted properly
// instead of trusted.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
