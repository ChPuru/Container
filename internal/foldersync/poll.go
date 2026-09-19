package foldersync

import (
	"context"
	"sort"
	"sync"
	"time"
)

// changes is what one poll found.
type changes struct {
	created  []string
	modified []string
	deleted  []string
}

// empty reports whether the poll found nothing at all.
func (c changes) empty() bool {
	return len(c.created) == 0 && len(c.modified) == 0 && len(c.deleted) == 0
}

// count returns the number of paths that changed.
func (c changes) count() int { return len(c.created) + len(c.modified) + len(c.deleted) }

// sortAll puts each list in a stable order, so callers and tests see the same
// thing every run; a map walk would not.
func (c *changes) sortAll() {
	sort.Strings(c.created)
	sort.Strings(c.modified)
	sort.Strings(c.deleted)
}

// poller detects changes in a tree that cannot deliver them any other way.
//
// This is the Windows side. An edit made by an editor running on Windows
// produces no inotify event inside the VM - not a delayed one, not a coalesced
// one, none at all - so the only way to notice it is to walk the tree and
// compare (size, mtime) per path against the previous walk. A rename shows up
// as a delete plus a create, which is exactly what it is from the outside.
//
// Walking a project tree over 9p is the expensive thing this package does, so
// the interval backs off exponentially from base to max while nothing is
// happening and snaps back to base the moment something does. An idle project
// costs one walk every max; a project being typed into costs one walk every
// base.
//
// A poller is not safe for concurrent use; Run owns it.
type poller struct {
	root string
	ig   *Ignorer

	base, max time.Duration

	mu       sync.Mutex
	interval time.Duration

	prev   tree
	primed bool
}

// newPoller returns a poller over root. The first call to poll primes the
// baseline and reports no changes, because everything that is already there on
// the first walk is not news.
func newPoller(root string, ig *Ignorer, base, max time.Duration) *poller {
	if base <= 0 {
		base = DefaultPollInterval
	}
	if max < base {
		max = base
	}
	return &poller{root: root, ig: ig, base: base, max: max, interval: base}
}

// currentInterval returns the interval the next poll should wait, after
// backoff.
func (p *poller) currentInterval() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.interval
}

// setBaseline replaces the poller's idea of the tree without walking it, which
// is how a completed sync pass hands over what it already observed. Without
// this the poller would see the syncer's own writes as user edits and schedule
// a pointless extra pass.
func (p *poller) setBaseline(t tree) {
	p.prev = t
	p.primed = true
}

// reset drops the baseline and the backoff, so the next poll primes again.
func (p *poller) reset() {
	p.prev = nil
	p.primed = false
	p.mu.Lock()
	p.interval = p.base
	p.mu.Unlock()
}

// poll walks the tree once and reports what changed since the previous walk,
// adjusting the backoff. Errors reading individual directories are not
// reported here: a scan that could not read one directory still tells the
// truth about the rest, and the reconciliation pass surfaces the failure.
func (p *poller) poll(ctx context.Context) (changes, error) {
	cur, _, err := scanTree(ctx, p.root, p.ig)
	if err != nil {
		return changes{}, err
	}

	var c changes
	if !p.primed {
		// Priming observes nothing, so it is not evidence of an idle tree and
		// must not advance the backoff.
		p.prev = cur
		p.primed = true
		return c, nil
	}

	for rel, e := range cur {
		old, ok := p.prev[rel]
		switch {
		case !ok:
			c.created = append(c.created, rel)
		case !e.sameAs(old):
			c.modified = append(c.modified, rel)
		}
	}
	for rel := range p.prev {
		if _, ok := cur[rel]; !ok {
			c.deleted = append(c.deleted, rel)
		}
	}
	c.sortAll()

	p.prev = cur
	p.backoff(!c.empty())
	return c, nil
}

// backoff doubles the interval up to max while the tree is quiet, and drops
// straight back to base the moment it is not.
func (p *poller) backoff(changed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if changed {
		p.interval = p.base
		return
	}
	next := p.interval * 2
	if next > p.max {
		next = p.max
	}
	if next < p.base {
		next = p.base
	}
	p.interval = next
}
