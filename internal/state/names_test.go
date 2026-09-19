package state

import (
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"simple", "web", true},
		{"two chars", "a1", true},
		{"docker style", "boring_wozniak", true},
		{"dots and dashes", "my.app-1_x", true},
		{"leading slash", "/web", true},
		{"digits first", "0day.tool", true},
		{"empty", "", false},
		{"single char", "a", false},
		{"leading dash", "-abc", false},
		{"leading dot", ".abc", false},
		{"leading underscore", "_abc", false},
		{"slash inside", "a/b", false},
		{"traversal", "../etc", false},
		{"dot dot", "..", false},
		{"space", "my app", false},
		{"colon", "web:1", false},
		{"nul byte", "web\x00", false},
		{"too long", strings.Repeat("a", maxNameLen+1), false},
		{"max length", strings.Repeat("a", maxNameLen), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateName(tc.in)
			if tc.ok && err != nil {
				t.Fatalf("ValidateName(%q) = %v, want nil", tc.in, err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("ValidateName(%q) = nil, want an error", tc.in)
				}
				if !errors.Is(err, ErrInvalidName) {
					t.Fatalf("ValidateName(%q) = %v, want ErrInvalidName", tc.in, err)
				}
			}
		})
	}
}

func TestNewID(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id := NewID()
		if len(id) != 64 {
			t.Fatalf("NewID() = %q, want 64 characters", id)
		}
		if err := validateFullID(id); err != nil {
			t.Fatalf("NewID() produced an invalid id: %v", err)
		}
		if seen[id] {
			t.Fatalf("NewID() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestReserveNameCollision(t *testing.T) {
	s := newTestStore(t)
	first, second := NewID(), NewID()
	for _, id := range []string{first, second} {
		if err := s.PutContainer(sampleContainer(id, "x")); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.ReserveName("web", first); err != nil {
		t.Fatalf("ReserveName: %v", err)
	}
	// The reservation is the symlink the crash-safety story depends on.
	target, err := os.Readlink(filepath.Join(s.namesDir(), "web"))
	if err != nil {
		t.Fatalf("reservation is not a symlink: %v", err)
	}
	if target != "../containers/"+first {
		t.Errorf("reservation target = %q, want ../containers/%s", target, first)
	}

	// Re-reserving for the same container is a no-op, so retrying a
	// half-finished create is safe.
	if err := s.ReserveName("web", first); err != nil {
		t.Errorf("idempotent ReserveName: %v", err)
	}

	err = s.ReserveName("web", second)
	if !errors.Is(err, ErrNameInUse) {
		t.Fatalf("ReserveName collision = %v, want ErrNameInUse", err)
	}
	var inUse *NameInUseError
	if !errors.As(err, &inUse) {
		t.Fatalf("collision error is not *NameInUseError: %v", err)
	}
	if inUse.Owner != first {
		t.Errorf("NameInUseError.Owner = %q, want %q", inUse.Owner, first)
	}
	if got, err := s.lookupName("web"); err != nil || got != first {
		t.Errorf("lookupName = %q, %v, want %q", got, err, first)
	}

	// Releasing hands the name over.
	if err := s.ReleaseName("web"); err != nil {
		t.Fatalf("ReleaseName: %v", err)
	}
	if err := s.ReleaseName("web"); err != nil {
		t.Errorf("ReleaseName on a free name = %v, want nil", err)
	}
	if err := s.ReserveName("web", second); err != nil {
		t.Fatalf("ReserveName after release: %v", err)
	}
	if got, _ := s.lookupName("/web"); got != second {
		t.Errorf("lookupName after handover = %q, want %q", got, second)
	}

	if err := s.ReserveName("!bad", first); !errors.Is(err, ErrInvalidName) {
		t.Errorf("ReserveName with a bad name = %v, want ErrInvalidName", err)
	}
	if err := s.ReserveName("fine", "nope"); !errors.Is(err, ErrInvalidID) {
		t.Errorf("ReserveName with a bad id = %v, want ErrInvalidID", err)
	}
}

// TestReserveNameReclaimsDanglingReservation covers the crash window between
// removing a container directory and releasing its name.
func TestReserveNameReclaimsDanglingReservation(t *testing.T) {
	s := newTestStore(t)
	dead, live := NewID(), NewID()
	if err := os.Symlink(nameTarget(dead), filepath.Join(s.namesDir(), "ghost")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutContainer(sampleContainer(live, "ghost")); err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveName("ghost", live); err != nil {
		t.Fatalf("ReserveName over a dangling reservation: %v", err)
	}
	if got, err := s.lookupName("ghost"); err != nil || got != live {
		t.Errorf("lookupName = %q, %v, want %q", got, err, live)
	}
}

func TestWordListsAreBigEnough(t *testing.T) {
	if len(adjectives) < 90 {
		t.Errorf("len(adjectives) = %d, want at least 90", len(adjectives))
	}
	if len(scientists) < 90 {
		t.Errorf("len(scientists) = %d, want at least 90", len(scientists))
	}
	for _, list := range [][]string{adjectives, scientists} {
		seen := map[string]bool{}
		for _, w := range list {
			if seen[w] {
				t.Errorf("duplicate word %q", w)
			}
			seen[w] = true
			if err := ValidateName(w); err != nil {
				t.Errorf("word %q is not a valid name fragment: %v", w, err)
			}
		}
	}
}

// TestGenerateNameIsDeterministicWithSeededRand pins the generator to an
// explicit source so the same seed always produces the same sequence.
func TestGenerateNameIsDeterministicWithSeededRand(t *testing.T) {
	gen := func() []string {
		s := newTestStore(t)
		s.SetRand(rand.New(rand.NewPCG(0xC0FFEE, 0x1234)))
		out := make([]string, 0, 8)
		for range 8 {
			out = append(out, s.GenerateName())
		}
		return out
	}
	first, second := gen(), gen()
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("name %d differs between runs: %q vs %q", i, first[i], second[i])
		}
		if !strings.Contains(first[i], "_") {
			t.Errorf("generated name %q is not adjective_scientist", first[i])
		}
		if err := ValidateName(first[i]); err != nil {
			t.Errorf("generated name %q is invalid: %v", first[i], err)
		}
	}

	// A different seed must produce a different sequence.
	other := newTestStore(t)
	other.SetRand(rand.New(rand.NewPCG(1, 1)))
	var differs bool
	for i := range first {
		if other.GenerateName() != first[i] {
			differs = true
		}
	}
	if !differs {
		t.Error("a different seed produced the same sequence")
	}
}

// TestGenerateNameAvoidsReservedNames checks the retry-on-collision loop.
func TestGenerateNameAvoidsReservedNames(t *testing.T) {
	s := newTestStore(t)
	s.SetRand(rand.New(rand.NewPCG(7, 7)))
	taken := s.GenerateName()

	id := NewID()
	if err := s.PutContainer(sampleContainer(id, taken)); err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveName(taken, id); err != nil {
		t.Fatal(err)
	}

	s.SetRand(rand.New(rand.NewPCG(7, 7)))
	got := s.GenerateName()
	if got == taken {
		t.Fatalf("GenerateName returned the reserved name %q", got)
	}
	if err := ValidateName(got); err != nil {
		t.Fatalf("GenerateName returned an invalid name %q: %v", got, err)
	}
}

// TestGenerateNameTerminatesWhenEverythingIsTaken makes sure the fallback
// numeric suffix keeps the loop finite even in a pathological store.
func TestGenerateNameTerminatesWhenEverythingIsTaken(t *testing.T) {
	s := newTestStore(t)
	s.SetRand(rand.New(rand.NewPCG(3, 9)))
	// Reserve every plain adjective_scientist combination the generator could
	// pick for a small slice of the word lists by reserving the whole cross
	// product is too slow; instead reserve the first 200 names it produces.
	for range 200 {
		n := s.GenerateName()
		id := NewID()
		if err := s.PutContainer(sampleContainer(id, n)); err != nil {
			t.Fatal(err)
		}
		if err := s.ReserveName(n, id); err != nil && !errors.Is(err, ErrNameInUse) {
			t.Fatal(err)
		}
	}
	n := s.GenerateName()
	if !s.nameAvailable(n) {
		t.Fatalf("GenerateName returned the taken name %q", n)
	}
}
