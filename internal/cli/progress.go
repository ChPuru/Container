package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/rahuldhali/hull/internal/client"
)

// progressRedraw throttles the terminal repaint. A pull emits a message per
// chunk per layer, which is far more often than a human can read.
const progressRedraw = 60 * time.Millisecond

// Progress renders a chunked JSON progress stream — a pull, a push, a load or
// a build.
//
// On a terminal it keeps one line per layer and repaints in place. Off a
// terminal it prints each distinct status once, with no cursor movement and no
// bars, so a redirected log or a CI transcript stays readable and a script
// never has to strip escape codes.
type Progress struct {
	out   io.Writer
	tty   bool
	quiet bool

	mu       sync.Mutex
	order    []string
	lines    map[string]string
	lastSeen map[string]string
	drawn    int
	lastDraw time.Time
	// auxID is the image id a build or load reported through its aux field.
	auxID string
	// failure is the mid-stream error, which arrives inside a 200 response
	// because the headers went out long before anything went wrong.
	failure error
}

// NewProgress builds a renderer for env's stdout. A quiet renderer prints
// nothing but the final identifiers, which is what "--quiet" means on pull,
// load and build.
func NewProgress(env *Env, quiet bool) *Progress {
	return &Progress{
		out:      env.Out,
		tty:      env.StdoutIsTerminal() && env.Color(),
		quiet:    quiet,
		lines:    map[string]string{},
		lastSeen: map[string]string{},
	}
}

// Handle consumes one progress message. It is the [client.ProgressFunc] the
// streaming calls take.
func (p *Progress) Handle(msg client.ProgressMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if msg.Error != "" || msg.ErrorDetail != nil {
		text := msg.Error
		if msg.ErrorDetail != nil && msg.ErrorDetail.Message != "" {
			text = msg.ErrorDetail.Message
		}
		p.failure = Errorf("%s", strings.TrimSpace(text))
		return p.failure
	}
	if len(msg.Aux) > 0 {
		p.readAux(msg.Aux)
	}
	if msg.Stream != "" {
		// Build output is raw text and must pass through untouched.
		p.clearLocked()
		if !p.quiet {
			fmt.Fprint(p.out, msg.Stream)
		}
		return nil
	}
	if msg.Status == "" {
		return nil
	}
	if p.quiet {
		return nil
	}
	if msg.ID == "" {
		p.clearLocked()
		fmt.Fprintln(p.out, msg.Status)
		return nil
	}
	line := msg.ID + ": " + msg.Status
	if msg.ProgressDetail != nil && msg.ProgressDetail.Total > 0 {
		line += "  " + renderBar(msg.ProgressDetail.Current, msg.ProgressDetail.Total, p.tty)
	}
	if _, known := p.lines[msg.ID]; !known {
		p.order = append(p.order, msg.ID)
	}
	p.lines[msg.ID] = line

	if !p.tty {
		// Off a terminal, only a change of phase is worth a line.
		if p.lastSeen[msg.ID] == msg.Status {
			return nil
		}
		p.lastSeen[msg.ID] = msg.Status
		fmt.Fprintf(p.out, "%s: %s\n", msg.ID, msg.Status)
		return nil
	}
	if time.Since(p.lastDraw) < progressRedraw {
		return nil
	}
	p.drawLocked()
	return nil
}

// readAux pulls the image id out of an aux payload, which is how a build and a
// load report what they produced.
func (p *Progress) readAux(raw json.RawMessage) {
	var aux struct {
		ID     string `json:"ID"`
		IDLow  string `json:"id"`
		Digest string `json:"Digest"`
	}
	if err := json.Unmarshal(raw, &aux); err != nil {
		return
	}
	switch {
	case aux.ID != "":
		p.auxID = aux.ID
	case aux.IDLow != "":
		p.auxID = aux.IDLow
	case aux.Digest != "":
		p.auxID = aux.Digest
	}
}

// drawLocked repaints the layer block in place. The caller holds the lock.
func (p *Progress) drawLocked() {
	if p.drawn > 0 {
		fmt.Fprintf(p.out, "\x1b[%dA", p.drawn)
	}
	for _, id := range p.order {
		fmt.Fprintf(p.out, "\x1b[2K%s\n", p.lines[id])
	}
	p.drawn = len(p.order)
	p.lastDraw = time.Now()
}

// clearLocked erases the in-place block so an unrelated line can be printed
// above it. The caller holds the lock.
func (p *Progress) clearLocked() {
	if !p.tty || p.drawn == 0 {
		return
	}
	fmt.Fprintf(p.out, "\x1b[%dA", p.drawn)
	for range p.drawn {
		fmt.Fprint(p.out, "\x1b[2K\n")
	}
	fmt.Fprintf(p.out, "\x1b[%dA", p.drawn)
	p.drawn = 0
	p.order = p.order[:0]
	p.lines = map[string]string{}
}

// Close paints the final state and returns any mid-stream failure.
func (p *Progress) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tty && len(p.order) > 0 {
		p.drawLocked()
	}
	return p.failure
}

// AuxID returns the image id the stream reported, if it reported one.
func (p *Progress) AuxID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.auxID
}

// barWidth is how many cells the in-place progress bar occupies.
const barWidth = 24

// renderBar draws a byte counter, with a bar only when the output is a
// terminal.
func renderBar(current, total int64, tty bool) string {
	counts := fmt.Sprintf("%s/%s", HumanSize(current), HumanSize(total))
	if !tty || total <= 0 {
		return counts
	}
	filled := int(float64(barWidth) * float64(current) / float64(total))
	if filled < 0 {
		filled = 0
	}
	if filled > barWidth {
		filled = barWidth
	}
	return "[" + strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled) + "] " + counts
}
