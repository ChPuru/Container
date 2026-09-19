package shim

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// flatten renders a ring snapshot as one string per stream plus the
// interleaved order, which is what an attacher actually replays.
func flatten(chunks []Chunk) (order string, stdout string, stderr string) {
	var o, so, se strings.Builder
	for _, c := range chunks {
		switch c.Stream {
		case KindStdout:
			o.WriteString("o")
			so.Write(c.Data)
		case KindStderr:
			o.WriteString("e")
			se.Write(c.Data)
		}
	}
	return o.String(), so.String(), se.String()
}

func TestRingBufferKeepsOrderAndStreams(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(1024)
	r.Add(KindStdout, []byte("one "))
	r.Add(KindStderr, []byte("ERR "))
	r.Add(KindStdout, []byte("two "))
	r.Add(KindStdout, []byte("three"))

	order, out, errs := flatten(r.Snapshot())
	if order != "oeo" {
		t.Errorf("record order = %q, want %q (adjacent same-stream writes coalesce)", order, "oeo")
	}
	if out != "one two three" {
		t.Errorf("stdout = %q, want %q", out, "one two three")
	}
	if errs != "ERR " {
		t.Errorf("stderr = %q, want %q", errs, "ERR ")
	}
	if got, want := r.Size(), len("one two three")+len("ERR "); got != want {
		t.Errorf("Size = %d, want %d", got, want)
	}
	if got := string(r.Bytes(KindStdout)); got != "one two three" {
		t.Errorf("Bytes(stdout) = %q", got)
	}
}

func TestRingBufferDropsOldestBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		max   int
		write []string
		want  string
	}{
		{
			name:  "fits exactly",
			max:   10,
			write: []string{"0123456789"},
			want:  "0123456789",
		},
		{
			name:  "one byte over trims the head",
			max:   10,
			write: []string{"0123456789", "A"},
			want:  "123456789A",
		},
		{
			name:  "several writes overflow",
			max:   8,
			write: []string{"aaaa", "bbbb", "cccc"},
			want:  "bbbbcccc",
		},
		{
			name:  "a partial head record is trimmed, not dropped",
			max:   6,
			write: []string{"abcdef", "gh"},
			want:  "cdefgh",
		},
		{
			name:  "a single oversized write keeps its tail",
			max:   5,
			write: []string{"0123456789"},
			want:  "56789",
		},
		{
			name:  "an oversized write discards everything before it",
			max:   5,
			write: []string{"xxxxx", "0123456789"},
			want:  "56789",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := NewRingBuffer(tt.max)
			for _, w := range tt.write {
				r.Add(KindStdout, []byte(w))
			}
			if got := string(r.Bytes(KindStdout)); got != tt.want {
				t.Errorf("contents = %q, want %q", got, tt.want)
			}
			if r.Size() > tt.max {
				t.Errorf("Size = %d, over the %d byte limit", r.Size(), tt.max)
			}
			if got, want := r.Size(), len(tt.want); got != want {
				t.Errorf("Size = %d, want %d", got, want)
			}
		})
	}
}

func TestRingBufferTrimsAcrossStreams(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(6)
	r.Add(KindStdout, []byte("aaaa"))
	r.Add(KindStderr, []byte("bbbb"))
	// Only the last 6 bytes survive: 2 of stdout's and all of stderr's.
	_, out, errs := flatten(r.Snapshot())
	if out != "aa" {
		t.Errorf("stdout = %q, want %q", out, "aa")
	}
	if errs != "bbbb" {
		t.Errorf("stderr = %q, want %q", errs, "bbbb")
	}
	if r.Size() != 6 {
		t.Errorf("Size = %d, want 6", r.Size())
	}
}

func TestRingBufferCoalescesUpToARecordCap(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(DefaultRingSize)
	// A screenful at a time, well past one record's cap.
	chunk := bytes.Repeat([]byte("x"), 1000)
	for i := 0; i < 100; i++ {
		r.Add(KindStdout, chunk)
	}
	snap := r.Snapshot()
	if r.Size() != DefaultRingSize {
		t.Errorf("Size = %d, want the ring full at %d", r.Size(), DefaultRingSize)
	}
	// The record count has to stay small so replaying the ring to a new
	// attacher is a handful of writes, not thousands.
	if len(snap) > DefaultRingSize/maxRingRecord+2 {
		t.Errorf("snapshot has %d records, want at most %d", len(snap), DefaultRingSize/maxRingRecord+2)
	}
	for i, c := range snap {
		if len(c.Data) > maxRingRecord {
			t.Errorf("record %d is %d bytes, over the %d cap", i, len(c.Data), maxRingRecord)
		}
	}
}

func TestRingBufferIgnoresEmptyWrites(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(16)
	r.Add(KindStdout, nil)
	r.Add(KindStdout, []byte{})
	if r.Size() != 0 || len(r.Snapshot()) != 0 {
		t.Fatalf("empty writes changed the ring: size=%d records=%d", r.Size(), len(r.Snapshot()))
	}
}

func TestRingBufferDefaultSize(t *testing.T) {
	t.Parallel()
	for _, max := range []int{0, -1} {
		r := NewRingBuffer(max)
		r.Add(KindStdout, bytes.Repeat([]byte("y"), DefaultRingSize+100))
		if r.Size() != DefaultRingSize {
			t.Errorf("NewRingBuffer(%d) held %d bytes, want %d", max, r.Size(), DefaultRingSize)
		}
	}
}

func TestRingBufferConcurrentWrites(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(4096)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				r.Add(KindStdout, []byte(fmt.Sprintf("%d-%d ", i, j)))
				r.Snapshot()
			}
		}(i)
	}
	wg.Wait()
	if r.Size() > 4096 {
		t.Fatalf("Size = %d, over the limit after concurrent writes", r.Size())
	}
}
