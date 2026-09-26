package tui

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/ChPuru/hull/internal/types"
)

// DetailTab selects what the detail pane shows for the selected container.
type DetailTab int

// The detail tabs, in cycle order.
const (
	// TabLogs is a live tail of the container's log.
	TabLogs DetailTab = iota
	// TabStats is the CPU and memory history as sparklines.
	TabStats
	// TabInspect is the container record as pretty JSON.
	TabInspect
	// TabPorts is the published port map.
	TabPorts
	// numTabs is the number of tabs, used for the cycle.
	numTabs
)

// tabTitles are the tab bar labels, in tab order.
var tabTitles = []string{"Logs", "Stats", "Inspect", "Ports"}

// String returns the tab's name as the tab bar shows it.
func (t DetailTab) String() string {
	if t < 0 || int(t) >= len(tabTitles) {
		return "?"
	}
	return tabTitles[t]
}

// ring is a fixed-capacity FIFO of the last n values. The dashboard keeps one
// per series and one for the event strip: the interesting history is always
// the recent history, and an unbounded slice in a process that runs all day is
// a leak with a nice name.
type ring[T any] struct {
	items []T
	next  int
	full  bool
}

// newRing returns a ring holding at most n values. A non-positive n yields a
// ring that holds one.
func newRing[T any](n int) *ring[T] {
	if n < 1 {
		n = 1
	}
	return &ring[T]{items: make([]T, n)}
}

// add appends v, dropping the oldest value when the ring is full.
func (r *ring[T]) add(v T) {
	r.items[r.next] = v
	r.next = (r.next + 1) % len(r.items)
	if r.next == 0 {
		r.full = true
	}
}

// len returns how many values the ring currently holds.
func (r *ring[T]) len() int {
	if r.full {
		return len(r.items)
	}
	return r.next
}

// slice returns the values oldest first, in a fresh slice.
func (r *ring[T]) slice() []T {
	n := r.len()
	out := make([]T, 0, n)
	if r.full {
		out = append(out, r.items[r.next:]...)
	}
	out = append(out, r.items[:r.next]...)
	return out
}

// last returns the newest value and whether there is one.
func (r *ring[T]) last() (T, bool) {
	var zero T
	if r.len() == 0 {
		return zero, false
	}
	idx := (r.next - 1 + len(r.items)) % len(r.items)
	return r.items[idx], true
}

// statSeries is one container's rolling CPU and memory history.
type statSeries struct {
	cpu  *ring[float64]
	mem  *ring[float64]
	last types.Stats
	seen bool
}

// overlayKind is which overlay, if any, is on top of the dashboard.
type overlayKind int

const (
	overlayNone overlayKind = iota
	overlayHelp
	overlayWarnings
	overlayConfirm
)

// CommandKind is an action the render loop must carry out against the engine
// on the model's behalf. The model never calls the engine itself: it is a pure
// state machine, so a test can drive it with keystrokes and assert on what it
// asked for.
type CommandKind int

// The commands the model can issue.
const (
	CmdNone CommandKind = iota
	CmdQuit
	CmdStart
	CmdStop
	CmdRestart
	CmdPause
	CmdUnpause
	CmdRemove
	CmdExec
	CmdRedraw
)

// Command is one request from the model to the render loop.
type Command struct {
	// Kind is what to do.
	Kind CommandKind
	// Container is the container to do it to, for the container commands.
	Container types.Container
	// Force is set for a removal, which the dashboard always does with
	// force because it asked the user first.
	Force bool
}

// DefaultStatsHistory is how many samples the stats sparklines keep: sixty
// one-second samples is the last minute, which is the window in which a
// container that has just started misbehaving is still recognisable.
const DefaultStatsHistory = 60

// DefaultEventHistory is how many engine events the strip keeps.
const DefaultEventHistory = 200

// DefaultLogHistory is how many log lines the logs tab keeps per container.
const DefaultLogHistory = 2000

// Model is the whole dashboard state: what the engine last said, what the user
// has selected, filtered and typed, and which overlay is up.
//
// It is deliberately free of goroutines, terminals and clients. Data arrives
// through the Set/Add methods, keystrokes through [Model.Apply], and the view
// is a pure function of the result - which is what makes the interesting parts
// of a TUI testable at all.
type Model struct {
	// Theme is the style set the view draws with.
	Theme Theme
	// Now returns the current time; tests substitute it.
	Now func() time.Time
	// StatsHistory is how many samples each sparkline keeps.
	StatsHistory int

	info Info
	disk DiskUsage

	containers []types.Container
	filtered   []types.Container
	table      Table

	mode        Mode
	overlay     overlayKind
	filter      string
	savedFilter string

	tab      DetailTab
	scroll   [numTabs]int
	selectID string

	series   map[string]*statSeries
	logs     map[string]*ring[LogLine]
	warnings map[string][]string
	events   *ring[types.Event]

	inspectID   string
	inspectText []string

	confirmText string
	confirmCmd  Command

	toast      string
	toastStyle Style
	toastUntil time.Time

	width, height int
	lay           Layout
}

// NewModel returns an empty model with the default theme and history sizes.
func NewModel() *Model {
	m := &Model{
		Theme:        DefaultTheme(),
		Now:          time.Now,
		StatsHistory: DefaultStatsHistory,
		series:       map[string]*statSeries{},
		logs:         map[string]*ring[LogLine]{},
		warnings:     map[string][]string{},
		events:       newRing[types.Event](DefaultEventHistory),
	}
	m.table.Columns = containerColumns()
	m.table.HeaderStyle = m.Theme.TableHeader
	m.table.RowStyle = m.Theme.TableRow
	m.table.SelectedStyle = m.Theme.TableSelected
	return m
}

// now returns the model's idea of the current time.
func (m *Model) now() time.Time {
	if m.Now == nil {
		return time.Now()
	}
	return m.Now()
}

// SetSize records the terminal size and recomputes the layout.
func (m *Model) SetSize(w, h int) {
	m.width, m.height = w, h
	m.lay = ComputeLayout(w, h)
	m.table.EnsureVisible(m.lay.Containers)
}

// Size returns the last size the model was told about.
func (m *Model) Size() (int, int) { return m.width, m.height }

// Layout returns the layout for the current size.
func (m *Model) Layout() Layout { return m.lay }

// Mode returns the current input mode, which decides how a keystroke is read.
func (m *Model) Mode() Mode { return m.mode }

// Tab returns the active detail tab.
func (m *Model) Tab() DetailTab { return m.tab }

// SetTab selects a detail tab.
func (m *Model) SetTab(t DetailTab) {
	if t < 0 || t >= numTabs {
		return
	}
	m.tab = t
}

// Filter returns the current filter text.
func (m *Model) Filter() string { return m.filter }

// SetFilter replaces the filter and reselects.
func (m *Model) SetFilter(s string) {
	m.filter = s
	m.refilter()
}

// SetInfo records the engine info the status bar draws from.
func (m *Model) SetInfo(i Info) { m.info = i }

// Info returns the last engine info the model was given.
func (m *Model) Info() Info { return m.info }

// SetDiskUsage records free space on the engine's data root.
func (m *Model) SetDiskUsage(d DiskUsage) { m.disk = d }

// SetContainers replaces the container list, keeping the selection on the same
// container if it is still there.
func (m *Model) SetContainers(cs []types.Container) {
	sorted := make([]types.Container, len(cs))
	copy(sorted, cs)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := stateRank(sorted[i].State), stateRank(sorted[j].State)
		if ri != rj {
			return ri < rj
		}
		if !sorted[i].Created.Equal(sorted[j].Created) {
			return sorted[i].Created.After(sorted[j].Created)
		}
		return sorted[i].Name < sorted[j].Name
	})
	m.containers = sorted
	m.refilter()
}

// Containers returns the unfiltered container list.
func (m *Model) Containers() []types.Container { return m.containers }

// stateRank orders the container list: what is running matters most, what is
// dead matters least.
func stateRank(s types.State) int {
	switch s {
	case types.StateRunning:
		return 0
	case types.StateRestarting:
		return 1
	case types.StatePaused:
		return 2
	case types.StateCreated:
		return 3
	case types.StateRemoving:
		return 4
	case types.StateExited:
		return 5
	default:
		return 6
	}
}

// refilter recomputes the visible rows and keeps the selection pinned to the
// same container id where it still exists.
func (m *Model) refilter() {
	m.filtered = m.filtered[:0]
	for _, c := range m.containers {
		if matchContainer(c, m.filter) {
			m.filtered = append(m.filtered, c)
		}
	}
	m.table.Rows = m.rows()
	idx := -1
	for i, c := range m.filtered {
		if c.ID == m.selectID {
			idx = i
			break
		}
	}
	if idx < 0 {
		idx = clampInt(m.table.Selected, 0, max(len(m.filtered)-1, 0))
	}
	m.table.Selected = idx
	m.table.EnsureVisible(m.lay.Containers)
	m.syncSelection()
}

// syncSelection records the id of the selected container so the selection
// survives the list being re-sorted under it.
func (m *Model) syncSelection() {
	if c, ok := m.Selected(); ok {
		m.selectID = c.ID
		return
	}
	m.selectID = ""
}

// matchContainer reports whether a container passes the filter. The filter is
// a case-insensitive substring match against name, id, image and state, which
// is what a user typing three letters means.
func matchContainer(c types.Container, filter string) bool {
	f := strings.TrimSpace(strings.ToLower(filter))
	if f == "" {
		return true
	}
	fields := []string{
		strings.ToLower(c.Name),
		strings.ToLower(c.ID),
		strings.ToLower(ImageName(c)),
		strings.ToLower(string(c.State)),
	}
	for _, v := range fields {
		if strings.Contains(v, f) {
			return true
		}
	}
	return false
}

// Selected returns the selected container, and false when the list is empty.
func (m *Model) Selected() (types.Container, bool) {
	if len(m.filtered) == 0 {
		return types.Container{}, false
	}
	idx := clampInt(m.table.Selected, 0, len(m.filtered)-1)
	return m.filtered[idx], true
}

// SelectedID returns the selected container's id, or "".
func (m *Model) SelectedID() string {
	c, ok := m.Selected()
	if !ok {
		return ""
	}
	return c.ID
}

// Visible returns the containers that pass the filter, in display order.
func (m *Model) Visible() []types.Container { return m.filtered }

// AddEvent records one engine event for the event strip.
func (m *Model) AddEvent(e types.Event) { m.events.add(e) }

// Events returns the recorded events, oldest first.
func (m *Model) Events() []types.Event { return m.events.slice() }

// AddLog records one log line for a container.
func (m *Model) AddLog(id string, line LogLine) {
	r, ok := m.logs[id]
	if !ok {
		r = newRing[LogLine](DefaultLogHistory)
		m.logs[id] = r
	}
	r.add(line)
}

// ClearLogs drops the recorded log of one container, which the log tailer does
// when it restarts a stream so the pane does not show the same lines twice.
func (m *Model) ClearLogs(id string) { delete(m.logs, id) }

// Logs returns the recorded log lines for a container, oldest first.
func (m *Model) Logs(id string) []LogLine {
	r, ok := m.logs[id]
	if !ok {
		return nil
	}
	return r.slice()
}

// AddStats records one stats sample for a container, deriving the CPU
// percentage and the cache-corrected memory figure the sparklines plot.
func (m *Model) AddStats(id string, s types.Stats) {
	hist := m.StatsHistory
	if hist <= 0 {
		hist = DefaultStatsHistory
	}
	ser, ok := m.series[id]
	if !ok {
		ser = &statSeries{cpu: newRing[float64](hist), mem: newRing[float64](hist)}
		m.series[id] = ser
	}
	ser.cpu.add(CPUPercent(s))
	ser.mem.add(float64(MemoryUsage(s)))
	ser.last = s
	ser.seen = true
}

// Stats returns the last sample recorded for a container.
func (m *Model) Stats(id string) (types.Stats, bool) {
	ser, ok := m.series[id]
	if !ok || !ser.seen {
		return types.Stats{}, false
	}
	return ser.last, true
}

// SetWarnings records the engine's create-time warnings for a container. They
// are the ones bundle.Generate returns when a resource limit cannot be
// enforced on this host, and the list marks such a container with a bang.
func (m *Model) SetWarnings(id string, w []string) {
	if len(w) == 0 {
		delete(m.warnings, id)
		return
	}
	m.warnings[id] = w
	m.table.Rows = m.rows()
}

// Warnings returns the recorded warnings for a container.
func (m *Model) Warnings(id string) []string { return m.warnings[id] }

// warningsFor returns everything known about one container's warnings: what
// the engine was asked for directly, falling back to what the container's own
// record carries. The fallback is what makes the list mark every warned
// container rather than only the one the user has selected, since the
// dashboard only inspects the selection.
func (m *Model) warningsFor(c types.Container) []string {
	if w := m.warnings[c.ID]; len(w) > 0 {
		return w
	}
	return ContainerWarnings(c)
}

// SetInspect records the pretty-printed inspect output for a container.
func (m *Model) SetInspect(id string, c types.Container) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		m.inspectID = id
		m.inspectText = []string{"inspect: " + err.Error()}
		return
	}
	m.inspectID = id
	m.inspectText = strings.Split(string(data), "\n")
}

// Toast shows a transient message on the status bar for a few seconds. It is
// how an action reports that it happened, or that it failed.
func (m *Model) Toast(msg string, style Style) {
	m.toast = msg
	m.toastStyle = style
	m.toastUntil = m.now().Add(4 * time.Second)
}

// Error shows a transient error on the status bar.
func (m *Model) Error(err error) {
	if err == nil {
		return
	}
	m.Toast(err.Error(), m.Theme.Error)
}

// toastText returns the live toast, or "" once it has expired.
func (m *Model) toastText() (string, Style) {
	if m.toast == "" || m.now().After(m.toastUntil) {
		return "", Style{}
	}
	return m.toast, m.toastStyle
}

// Apply feeds one keystroke to the model and returns whatever the render loop
// must now do on its behalf.
func (m *Model) Apply(k Key) Command {
	action := Dispatch(m.mode, k)
	switch m.mode {
	case ModeHelp:
		if action == ActionQuit {
			return Command{Kind: CmdQuit}
		}
		if action == ActionRedraw {
			return Command{Kind: CmdRedraw}
		}
		m.mode = ModeNormal
		m.overlay = overlayNone
		return Command{}
	case ModeConfirm:
		switch action {
		case ActionQuit:
			return Command{Kind: CmdQuit}
		case ActionConfirmYes:
			cmd := m.confirmCmd
			m.mode = ModeNormal
			m.overlay = overlayNone
			m.confirmCmd = Command{}
			return cmd
		case ActionConfirmNo:
			m.mode = ModeNormal
			m.overlay = overlayNone
			m.confirmCmd = Command{}
		}
		return Command{}
	case ModeFilter:
		return m.applyFilterMode(action, k)
	}
	return m.applyNormal(action, k)
}

// applyFilterMode handles the keys of the filter prompt. Filtering is live:
// the list narrows as the user types, and escape puts back what was there
// before.
func (m *Model) applyFilterMode(action Action, k Key) Command {
	switch action {
	case ActionQuit:
		return Command{Kind: CmdQuit}
	case ActionFilterInput:
		m.filter += string(k.Rune)
		m.refilter()
	case ActionFilterBackspace:
		r := []rune(m.filter)
		if len(r) > 0 {
			m.filter = string(r[:len(r)-1])
			m.refilter()
		}
	case ActionFilterClear:
		m.filter = ""
		m.refilter()
	case ActionFilterAccept:
		m.mode = ModeNormal
	case ActionFilterCancel:
		m.filter = m.savedFilter
		m.mode = ModeNormal
		m.refilter()
	case ActionSelectUp:
		m.move(-1)
	case ActionSelectDown:
		m.move(1)
	case ActionPageUp:
		m.scrollDetail(-m.detailPage())
	case ActionPageDown:
		m.scrollDetail(m.detailPage())
	}
	return Command{}
}

// applyNormal handles the keys of the dashboard proper.
func (m *Model) applyNormal(action Action, k Key) Command {
	sel, hasSel := m.Selected()
	switch action {
	case ActionQuit:
		return Command{Kind: CmdQuit}
	case ActionRedraw:
		return Command{Kind: CmdRedraw}
	case ActionSelectUp:
		m.move(-1)
	case ActionSelectDown:
		m.move(1)
	case ActionSelectTop:
		m.table.Selected = 0
		m.afterMove()
	case ActionSelectBottom:
		m.table.Selected = max(len(m.filtered)-1, 0)
		m.afterMove()
	case ActionNextTab:
		m.tab = (m.tab + 1) % numTabs
	case ActionPrevTab:
		m.tab = (m.tab + numTabs - 1) % numTabs
	case ActionSelectTab:
		if t, ok := tabForKey(k); ok {
			m.tab = t
		}
	case ActionScrollUp:
		m.scrollDetail(-1)
	case ActionScrollDown:
		m.scrollDetail(1)
	case ActionPageUp:
		m.scrollDetail(-m.detailPage())
	case ActionPageDown:
		m.scrollDetail(m.detailPage())
	case ActionFilterBegin:
		m.savedFilter = m.filter
		m.mode = ModeFilter
	case ActionHelp:
		m.mode = ModeHelp
		m.overlay = overlayHelp
	case ActionWarnings:
		m.mode = ModeHelp
		m.overlay = overlayWarnings
	case ActionDismiss:
		m.overlay = overlayNone
		if m.filter != "" {
			m.filter = ""
			m.refilter()
		}
	case ActionStop:
		if hasSel {
			m.Toast("stopping "+sel.Name, m.Theme.Warn)
			return Command{Kind: CmdStop, Container: sel}
		}
	case ActionStart:
		if hasSel {
			m.Toast("starting "+sel.Name, m.Theme.Base)
			return Command{Kind: CmdStart, Container: sel}
		}
	case ActionRestart:
		if hasSel {
			m.Toast("restarting "+sel.Name, m.Theme.Base)
			return Command{Kind: CmdRestart, Container: sel}
		}
	case ActionPause:
		if hasSel {
			if sel.State == types.StatePaused {
				m.Toast("unpausing "+sel.Name, m.Theme.Base)
				return Command{Kind: CmdUnpause, Container: sel}
			}
			m.Toast("pausing "+sel.Name, m.Theme.Warn)
			return Command{Kind: CmdPause, Container: sel}
		}
	case ActionExec:
		if hasSel {
			return Command{Kind: CmdExec, Container: sel}
		}
	case ActionDelete:
		if hasSel {
			m.mode = ModeConfirm
			m.overlay = overlayConfirm
			m.confirmText = "delete " + sel.Name + " (" + ShortID(sel.ID) + ")?"
			m.confirmCmd = Command{Kind: CmdRemove, Container: sel, Force: true}
		}
	}
	return Command{}
}

// move shifts the selection by delta rows.
func (m *Model) move(delta int) {
	if len(m.filtered) == 0 {
		return
	}
	m.table.Selected = clampInt(m.table.Selected+delta, 0, len(m.filtered)-1)
	m.afterMove()
}

// afterMove re-pins the selection, scrolls the table and resets the detail
// pane, which belongs to the container that was selected, not to the pane.
func (m *Model) afterMove() {
	m.table.EnsureVisible(m.lay.Containers)
	prev := m.selectID
	m.syncSelection()
	if prev != m.selectID {
		m.scroll = [numTabs]int{}
	}
}

// detailPage is how many lines a page-up or page-down moves.
func (m *Model) detailPage() int {
	if m.lay.Detail.H > 1 {
		return m.lay.Detail.H - 1
	}
	return 1
}

// scrollDetail scrolls the active detail tab by n lines, negative for up.
//
// The two anchors differ and the sign has to follow. The inspect pane is
// anchored at the top, so its offset counts down the document and scrolling up
// decreases it. The logs pane is anchored at the bottom - it follows the
// newest line - so its offset counts lines back from the end, and scrolling up
// increases it. Getting this wrong makes page-up show newer lines, which is
// the sort of thing nobody reports as a bug and everybody notices.
func (m *Model) scrollDetail(n int) {
	if n == 0 {
		return
	}
	idx := int(m.tab)
	if idx < 0 || idx >= int(numTabs) {
		return
	}
	if m.tab == TabLogs {
		n = -n
	}
	m.scroll[idx] += n
	if m.scroll[idx] < 0 {
		m.scroll[idx] = 0
	}
}

// Following reports whether the logs pane is pinned to the newest line. It
// stops following when the user scrolls back, and follows again once they
// return to the bottom.
func (m *Model) Following() bool { return m.scroll[TabLogs] == 0 }

// containerColumns is the container table's column set. Priority orders what
// is dropped as the terminal narrows: ports first, then the image, then the
// resource columns - identity and state are never dropped.
func containerColumns() []Column {
	return []Column{
		{Title: "id", Min: 12, Max: 12},
		{Title: "name", Min: 10, Max: 28, Weight: 2},
		{Title: "image", Min: 10, Max: 40, Weight: 3, Priority: 3},
		{Title: "state", Min: 9, Max: 20, Priority: 1},
		{Title: "uptime", Min: 7, Max: 9, Align: AlignRight, Priority: 2},
		{Title: "cpu", Min: 6, Max: 7, Align: AlignRight, Priority: 5},
		{Title: "mem", Min: 7, Max: 9, Align: AlignRight, Priority: 4},
		{Title: "ports", Min: 10, Weight: 3, Priority: 6},
	}
}

// rows builds the table rows from the filtered container list.
func (m *Model) rows() []Row {
	now := m.now()
	out := make([]Row, 0, len(m.filtered))
	for _, c := range m.filtered {
		cpu, mem := "-", "-"
		if s, ok := m.Stats(c.ID); ok {
			cpu = HumanPercent(CPUPercent(s))
			mem = HumanBytes(MemoryUsage(s))
		}
		name := c.Name
		if len(m.warningsFor(c)) > 0 {
			name = "! " + name
		}
		out = append(out, Row{
			Key: c.ID,
			Cells: []string{
				ShortID(c.ID),
				name,
				ImageName(c),
				StateSummary(c),
				HumanDuration(Uptime(c, now)),
				cpu,
				mem,
				strings.Join(PortStrings(c), " "),
			},
			Style: m.Theme.stateStyle(c),
		})
	}
	return out
}

// Refresh rebuilds the derived view state. The render loop calls it once per
// frame so uptimes and rates advance even when nothing arrived from the
// engine.
func (m *Model) Refresh() {
	m.table.Rows = m.rows()
	m.table.HeaderStyle = m.Theme.TableHeader
	m.table.RowStyle = m.Theme.TableRow
	m.table.SelectedStyle = m.Theme.TableSelected
	m.table.EnsureVisible(m.lay.Containers)
}
