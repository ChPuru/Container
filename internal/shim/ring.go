package shim

import "sync"

// DefaultRingSize is how much recent container output the shim keeps so a
// client that attaches late sees context immediately instead of a blank
// screen. 64 KiB is roughly a screenful of a build log.
const DefaultRingSize = 64 << 10

// maxRingRecord caps one coalesced ring record. Bounding it keeps the record
// count small (a full ring holds at most DefaultRingSize/maxRingRecord + 2
// records) so replaying the ring to a new attacher is a handful of writes.
const maxRingRecord = 8 << 10

// Chunk is one run of container output on one stream. Data is owned by the
// ring or the hub and must not be modified by a receiver.
type Chunk struct {
	// Stream is KindStdout or KindStderr.
	Stream byte
	Data   []byte
}

// RingBuffer holds the most recent bytes of container output, tagged by
// stream and in order. It is safe for concurrent use.
//
// When the buffer is full the oldest bytes are dropped, trimming the leading
// record rather than discarding it whole, so the replay boundary is exact.
type RingBuffer struct {
	mu   sync.Mutex
	max  int
	size int
	recs []Chunk
}

// NewRingBuffer returns a ring holding at most max bytes. A max of zero or
// less uses DefaultRingSize.
func NewRingBuffer(max int) *RingBuffer {
	if max <= 0 {
		max = DefaultRingSize
	}
	return &RingBuffer{max: max}
}

// Add appends p to the ring, copying it. Adjacent writes on the same stream
// are coalesced up to maxRingRecord bytes.
func (r *RingBuffer) Add(stream byte, p []byte) {
	if len(p) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// A single write larger than the ring can only leave its tail behind.
	if len(p) >= r.max {
		p = p[len(p)-r.max:]
		r.recs = r.recs[:0]
		r.size = 0
	}

	for len(p) > 0 {
		last := len(r.recs) - 1
		if last >= 0 && r.recs[last].Stream == stream && len(r.recs[last].Data) < maxRingRecord {
			n := min(len(p), maxRingRecord-len(r.recs[last].Data))
			r.recs[last].Data = append(r.recs[last].Data, p[:n]...)
			r.size += n
			p = p[n:]
			continue
		}
		n := min(len(p), maxRingRecord)
		data := make([]byte, n)
		copy(data, p[:n])
		r.recs = append(r.recs, Chunk{Stream: stream, Data: data})
		r.size += n
		p = p[n:]
	}
	r.trim()
}

// trim drops the oldest bytes until the ring is within its limit. The caller
// holds r.mu.
func (r *RingBuffer) trim() {
	for r.size > r.max && len(r.recs) > 0 {
		over := r.size - r.max
		head := &r.recs[0]
		if len(head.Data) > over {
			// Trim the front of the oldest record. Re-slicing keeps the
			// backing array alive but the record is rewritten below.
			trimmed := make([]byte, len(head.Data)-over)
			copy(trimmed, head.Data[over:])
			head.Data = trimmed
			r.size -= over
			return
		}
		r.size -= len(head.Data)
		head.Data = nil // let the dropped bytes go even though the array slides
		r.recs = r.recs[1:]
	}
	if len(r.recs) == 0 {
		r.recs = nil
		r.size = 0
	}
}

// Snapshot returns the ring's contents oldest first. The returned Chunks share
// the ring's byte slices, which the ring only ever appends to or replaces, so
// a receiver may read them but must not write to them.
func (r *RingBuffer) Snapshot() []Chunk {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Chunk, len(r.recs))
	copy(out, r.recs)
	return out
}

// Size reports how many bytes the ring currently holds.
func (r *RingBuffer) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

// Bytes returns the ring's contents for one stream, concatenated. It exists
// for tests and for the "last output" line in a state dump.
func (r *RingBuffer) Bytes(stream byte) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []byte
	for _, rec := range r.recs {
		if rec.Stream == stream {
			out = append(out, rec.Data...)
		}
	}
	return out
}
