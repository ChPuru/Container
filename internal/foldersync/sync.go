package foldersync

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// pairState is what the syncer remembers about one path after a pass: the
// observed state of each side. It is the baseline that lets the next pass tell
// "created on the left" from "deleted on the right" - two situations that look
// identical if all you have is the two current trees.
//
// There is deliberately no on-disk persistence. A freshly started Syncer has
// no baseline, so its first pass treats every one-sided path as a creation and
// propagates it, never as a deletion. Losing files because a daemon restarted
// is not a trade anyone would accept.
type pairState struct {
	host   entry
	vol    entry
	hostOK bool
	volOK  bool
}

// get returns one side of the pair.
func (p pairState) get(side Side) (entry, bool) {
	if side == SideHost {
		return p.host, p.hostOK
	}
	return p.vol, p.volOK
}

// pendingDelete is a directory removal held back until the end of the pass, so
// that a directory is only removed after its children have been.
type pendingDelete struct {
	side Side
	rel  string
	e    entry
}

// Sync runs one reconciliation pass over both trees and returns what it did.
// It is safe to call while Run is going: passes are serialised.
//
// The returned error is fatal to the pass (the context was cancelled, or a
// root could not be walked at all). Per-path failures are not: they land in
// Result.Errors and in an EventError, and the rest of the tree is still
// reconciled.
func (s *Syncer) Sync(ctx context.Context) (Result, error) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	return s.syncLocked(ctx)
}

// syncLocked is Sync with s.syncMu already held.
func (s *Syncer) syncLocked(ctx context.Context) (Result, error) {
	res := Result{Started: time.Now()}
	if err := ctx.Err(); err != nil {
		return res, err
	}

	hostTree, hostStats, err := scanTree(ctx, s.host, s.ig)
	if err != nil {
		return res, fmt.Errorf("foldersync: scan host %s: %w", s.host, err)
	}
	volTree, volStats, err := scanTree(ctx, s.volume, s.ig)
	if err != nil {
		return res, fmt.Errorf("foldersync: scan volume %s: %w", s.volume, err)
	}
	res.Scanned = len(hostTree) + len(volTree)
	res.Ignored = hostStats.ignored + volStats.ignored
	for _, e := range append(append([]error(nil), hostStats.errs...), volStats.errs...) {
		s.fail(&res, "", e)
	}

	rels := unionKeys(hostTree, volTree, s.prev)
	next := make(map[string]pairState, len(rels))
	var deferred []pendingDelete
	now := time.Now()

	// Sorted order puts a parent before its children, so a directory exists
	// before anything is written into it.
	for _, rel := range rels {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		h, hOK := hostTree[rel]
		v, vOK := volTree[rel]
		st := s.reconcile(rel, h, hOK, v, vOK, s.prev[rel], &res, &deferred, now)
		if st.hostOK || st.volOK {
			next[rel] = st
		}
	}

	// Directory removals run last, deepest first, so children are gone by the
	// time their parent is tried.
	sort.Slice(deferred, func(i, j int) bool { return deferred[i].rel > deferred[j].rel })
	for _, d := range deferred {
		if err := s.removeEntry(d.side, d.rel, d.e); err != nil {
			s.fail(&res, d.rel, err)
			continue
		}
		s.countDelete(&res, d.side)
		s.emit(Event{Kind: EventDelete, Path: d.rel, Side: d.side})
		st := next[d.rel]
		if d.side == SideHost {
			st.hostOK = false
		} else {
			st.volOK = false
		}
		if !st.hostOK && !st.volOK {
			delete(next, d.rel)
		} else {
			next[d.rel] = st
		}
	}

	s.prev = next
	res.Duration = time.Since(res.Started)

	s.mu.Lock()
	s.status.Syncs++
	s.status.LastSync = time.Now()
	s.status.LastResult = res
	s.status.Conflicts += uint64(res.Conflicts)
	s.mu.Unlock()

	s.emit(Event{Kind: EventSync, Result: res})
	return res, nil
}

// reconcile decides and performs what happens to one path, and returns the
// state to record for it.
//
// The decision is made against the baseline, not against a comparison of the
// two sides, because only the baseline distinguishes a creation from a
// deletion. A side has "changed" when it differs from what the last pass
// observed there; with no baseline at all (the first pass), every side that
// exists counts as changed, which is what makes a first pass treat a
// divergence as a conflict rather than silently picking a winner.
func (s *Syncer) reconcile(rel string, h entry, hOK bool, v entry, vOK bool, prev pairState, res *Result, deferred *[]pendingDelete, now time.Time) pairState {
	hostChanged := hOK != prev.hostOK || (hOK && prev.hostOK && !h.sameAs(prev.host))
	volChanged := vOK != prev.volOK || (vOK && prev.volOK && !v.sameAs(prev.vol))

	cur := pairState{host: h, hostOK: hOK, vol: v, volOK: vOK}

	// Nothing has moved on either side since the last pass. If the two sides
	// disagree, they disagreed then too - a previous copy failed, and it was
	// reported then. Re-deciding here would turn a reported failure into an
	// endless copy loop.
	if !hostChanged && !volChanged {
		return cur
	}

	switch {
	case hOK && vOK:
		if equivalent(h, v, s.tol) {
			return cur
		}
		conflict := hostChanged && volChanged
		win := s.winner(hostChanged, volChanged, h, v)
		lose := other(win)
		loser, _ := cur.get(lose)

		var kept string
		if conflict {
			res.Conflicts++
			k, err := s.preserveLoser(lose, rel, loser, now)
			if err != nil {
				s.fail(res, rel, err)
			}
			kept = k
			s.emit(Event{
				Kind:        EventConflict,
				Path:        rel,
				Side:        win,
				LoserSide:   lose,
				HostMTime:   h.mtime,
				VolumeMTime: v.mtime,
				Kept:        kept,
			})
		}
		if !s.canWrite(lose) {
			return s.observe(rel, res)
		}
		winner, _ := cur.get(win)
		s.doCopy(rel, win, lose, winner, res)
		return s.observe(rel, res)

	case hOK:
		s.oneSided(rel, SideHost, h, hostChanged, prev.volOK, res, deferred)
		return s.observe(rel, res)

	case vOK:
		s.oneSided(rel, SideVolume, v, volChanged, prev.hostOK, res, deferred)
		return s.observe(rel, res)

	default:
		// Gone from both sides. Drop it from the baseline.
		return pairState{}
	}
}

// oneSided handles a path that exists on exactly one side: either it was just
// created there, or the other side deleted it.
func (s *Syncer) oneSided(rel string, present Side, e entry, presentChanged, wasOnOther bool, res *Result, deferred *[]pendingDelete) {
	missing := other(present)

	switch {
	case wasOnOther && !presentChanged:
		// The other side deleted it and this side has not touched it since:
		// propagate the deletion. When the direction forbids writing this
		// side, the other side is not entitled to delete anything, so the
		// file is put back instead.
		if !s.canWrite(present) {
			if s.canWrite(missing) {
				s.doCopy(rel, present, missing, e, res)
			}
			return
		}
		if e.kind == kindDir {
			*deferred = append(*deferred, pendingDelete{side: present, rel: rel, e: e})
			return
		}
		if err := s.removeEntry(present, rel, e); err != nil {
			s.fail(res, rel, err)
			return
		}
		s.countDelete(res, present)
		s.emit(Event{Kind: EventDelete, Path: rel, Side: present})

	case wasOnOther && presentChanged:
		// Deleted on one side, modified on the other. There is no timestamp
		// on a deletion to compare against, so the modification wins - the
		// bytes that exist are worth more than the ones that do not - and the
		// user is told.
		res.Conflicts++
		hostM, volM := e.mtime, time.Time{}
		if present == SideVolume {
			hostM, volM = time.Time{}, e.mtime
		}
		s.emit(Event{
			Kind:        EventConflict,
			Path:        rel,
			Side:        present,
			LoserSide:   missing,
			HostMTime:   hostM,
			VolumeMTime: volM,
			Message:     fmt.Sprintf("conflict %s: deleted on %s, modified on %s; the modification wins", rel, missing, present),
		})
		if s.canWrite(missing) {
			s.doCopy(rel, present, missing, e, res)
		}

	default:
		// New here, never seen there.
		if s.canWrite(missing) {
			s.doCopy(rel, present, missing, e, res)
		}
	}
}

// winner picks the side whose version survives a divergence.
//
// A one-way direction always has an answer: the source of truth wins, even
// when it is the older copy. Bidirectionally, the side that changed wins; when
// both changed, the newest mtime wins and a tie goes to the host, because the
// host is where the human is typing.
func (s *Syncer) winner(hostChanged, volChanged bool, h, v entry) Side {
	switch s.cfg.Direction {
	case HostToVolume:
		return SideHost
	case VolumeToHost:
		return SideVolume
	}
	switch {
	case hostChanged && !volChanged:
		return SideHost
	case volChanged && !hostChanged:
		return SideVolume
	default:
		if v.mtime.After(h.mtime) {
			return SideVolume
		}
		return SideHost
	}
}

// doCopy performs one copy and books it.
func (s *Syncer) doCopy(rel string, from, to Side, e entry, res *Result) {
	n, err := s.copyEntry(rel, from, to, e)
	if err != nil {
		s.fail(res, rel, err)
		return
	}
	res.Bytes += n
	if to == SideHost {
		res.ToHost++
	} else {
		res.ToVolume++
	}
	s.emit(Event{Kind: EventCopy, Path: rel, Side: to, From: from, Size: n})
}

// countDelete books one removal.
func (s *Syncer) countDelete(res *Result, side Side) {
	if side == SideHost {
		res.DeletedHost++
	} else {
		res.DeletedVolume++
	}
}

// observe re-reads both sides of one path after the pass has written to it, so
// the recorded baseline is what the filesystems actually hold. On drvfs that
// is not always what was asked for - a mode that did not stick, a timestamp
// that was rounded - and recording the request rather than the result would
// make the next pass see a phantom change.
func (s *Syncer) observe(rel string, res *Result) pairState {
	var st pairState
	if e, ok, err := statEntry(s.host, rel); err != nil {
		s.fail(res, rel, err)
	} else {
		st.host, st.hostOK = e, ok
	}
	if e, ok, err := statEntry(s.volume, rel); err != nil {
		s.fail(res, rel, err)
	} else {
		st.vol, st.volOK = e, ok
	}
	return st
}

// unionKeys returns every path named by either tree or by the baseline, sorted
// so that a parent sorts before everything beneath it.
func unionKeys(a, b tree, prev map[string]pairState) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	for k := range prev {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// hostBaseline projects the post-pass baseline onto the host side, which is
// exactly the tree the host poller should compare against next. Handing it
// over means the poller does not report the syncer's own writes as user
// changes and trigger a pointless second pass.
func hostBaseline(prev map[string]pairState) tree {
	t := make(tree, len(prev))
	for rel, st := range prev {
		if st.hostOK {
			t[rel] = st.host
		}
	}
	return t
}

// volumeBaseline is hostBaseline for the volume side, used when the volume is
// polled rather than watched.
func volumeBaseline(prev map[string]pairState) tree {
	t := make(tree, len(prev))
	for rel, st := range prev {
		if st.volOK {
			t[rel] = st.vol
		}
	}
	return t
}
