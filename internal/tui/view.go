package tui

import (
	"strconv"
	"strings"

	"github.com/rahuldhali/hull/internal/types"
)

// Render draws the whole dashboard into b, which must be the size the model
// was last told about. It is a pure function of the model: no engine call, no
// clock read beyond Model.Now, and no terminal write, so a test can render a
// frame and assert on the characters.
func (m *Model) Render(b Buffer) {
	b.Clear()
	if m.lay.TooSmall {
		msg := "terminal too small - need " +
			strconv.Itoa(MinUsableWidth) + "x" + strconv.Itoa(MinUsableHeight)
		b.DrawTextIn(b.Bounds(), 0, 0, msg, m.Theme.Warn)
		return
	}

	m.renderContainers(b, m.lay.Containers)
	m.renderTabs(b, m.lay.Tabs)
	m.renderDetail(b, m.lay.Detail)
	m.renderEvents(b, m.lay.Events)
	m.renderStatus(b, m.lay.Status)
	m.renderOverlay(b)
}

// renderContainers draws the container list pane.
func (m *Model) renderContainers(b Buffer, r Rect) {
	if r.Empty() {
		return
	}
	right := strconv.Itoa(len(m.filtered)) + "/" + strconv.Itoa(len(m.containers))
	if m.filter != "" {
		right = "/" + Truncate(m.filter, 16) + "  " + right
	}
	PaneTitle(b, Rect{X: r.X, Y: r.Y, W: r.W, H: 1}, "containers", right,
		m.Theme.PaneTitle, m.Theme.Rule)

	body := Rect{X: r.X, Y: r.Y + 1, W: r.W, H: r.H - 1}
	if body.Empty() {
		return
	}
	m.table.HideHeader = body.H < 3
	m.table.EnsureVisible(body)
	if len(m.table.Rows) == 0 {
		msg := "no containers"
		if m.filter != "" {
			msg = "no containers match " + strconv.Quote(m.filter)
		}
		b.DrawTextIn(body, body.X, body.Y, msg, m.Theme.Dim)
		return
	}
	m.table.Render(b, body)
}

// renderTabs draws the detail pane's tab bar, captioned with the selection.
func (m *Model) renderTabs(b Buffer, r Rect) {
	if r.Empty() {
		return
	}
	suffix := ""
	if c, ok := m.Selected(); ok {
		suffix = c.Name + " " + ShortID(c.ID)
	}
	Tabs{
		Titles:      tabTitles,
		Active:      int(m.tab),
		Style:       m.Theme.TabInactive,
		ActiveStyle: m.Theme.TabActive,
		SuffixStyle: m.Theme.Dim,
		Suffix:      suffix,
	}.Render(b, r)
}

// renderDetail draws the body of the detail pane for the active tab.
func (m *Model) renderDetail(b Buffer, r Rect) {
	if r.Empty() {
		return
	}
	c, ok := m.Selected()
	if !ok {
		b.DrawTextIn(r, r.X, r.Y, "nothing selected", m.Theme.Dim)
		return
	}
	switch m.tab {
	case TabLogs:
		m.renderLogs(b, r, c)
	case TabStats:
		m.renderStats(b, r, c)
	case TabInspect:
		m.renderInspect(b, r, c)
	case TabPorts:
		m.renderPorts(b, r, c)
	}
}

// renderLogs draws the live log tail, newest at the bottom.
func (m *Model) renderLogs(b Buffer, r Rect, c types.Container) {
	lines := m.Logs(c.ID)
	if len(lines) == 0 {
		b.DrawTextIn(r, r.X, r.Y, "waiting for log output...", m.Theme.Dim)
		return
	}
	// The pane shows a window ending scroll lines above the newest line.
	end := len(lines) - m.scroll[TabLogs]
	end = clampInt(end, 1, len(lines))
	start := max(end-r.H, 0)
	for i, line := range lines[start:end] {
		style := m.Theme.Base
		if line.Stream == "stderr" {
			style = m.Theme.Error.Without(AttrBold)
		}
		text := line.Line
		if !line.Time.IsZero() {
			text = line.Time.Format("15:04:05") + " " + text
		}
		b.DrawTextIn(r, r.X, r.Y+i, strings.TrimRight(text, "\r"), style)
	}
	if m.scroll[TabLogs] > 0 {
		tag := " +" + strconv.Itoa(m.scroll[TabLogs]) + " newer "
		b.DrawTextIn(r, r.Right()-len([]rune(tag)), r.Bottom()-1, tag, m.Theme.Warn)
	}
}

// renderStats draws the CPU and memory sparklines and the current figures.
func (m *Model) renderStats(b Buffer, r Rect, c types.Container) {
	ser, ok := m.series[c.ID]
	if !ok || !ser.seen {
		b.DrawTextIn(r, r.X, r.Y, "no stats yet - the container may not be running", m.Theme.Dim)
		return
	}
	s := ser.last
	y := r.Y

	cpuNow, _ := ser.cpu.last()
	Sparkbar{
		Label:     "cpu ",
		Values:    ser.cpu.slice(),
		Current:   Pad(HumanPercent(cpuNow), 6, AlignRight),
		Style:     m.Theme.Base,
		LineStyle: m.Theme.Spark,
	}.Render(b, Rect{X: r.X, Y: y, W: r.W, H: 1})
	y++
	if y >= r.Bottom() {
		return
	}

	memNow, _ := ser.mem.last()
	memLabel := HumanBytes(uint64(memNow))
	memMax := 0.0
	if s.MemoryLimit > 0 {
		memMax = float64(s.MemoryLimit)
		memLabel += "/" + HumanBytes(s.MemoryLimit)
	}
	Sparkbar{
		Label:     "mem ",
		Values:    ser.mem.slice(),
		Current:   memLabel,
		Max:       memMax,
		Style:     m.Theme.Base,
		LineStyle: m.Theme.Spark,
	}.Render(b, Rect{X: r.X, Y: y, W: r.W, H: 1})
	y += 2

	rows := [][2]string{
		{"cpus", strconv.Itoa(s.OnlineCPUs)},
		{"memory", HumanBytes(MemoryUsage(s)) + " of " + limitText(s.MemoryLimit) +
			" (" + HumanPercent(MemoryPercent(s)) + ")"},
		{"cache", HumanBytes(s.MemoryCache)},
		{"pids", strconv.FormatUint(s.PidsCurrent, 10) + " of " + limitText(s.PidsLimit)},
		{"net", "rx " + HumanBytes(s.RxBytes) + "  tx " + HumanBytes(s.TxBytes)},
		{"block", "read " + HumanBytes(s.BlkRead) + "  write " + HumanBytes(s.BlkWrite)},
		{"sampled", s.Read.Format("15:04:05")},
	}
	if s.MemoryLimit == 0 {
		rows = append(rows, [2]string{"limits",
			"not enforced - no delegated cgroup v2 controllers on this host"})
	}
	for _, kv := range rows {
		if y >= r.Bottom() {
			return
		}
		x := b.DrawTextIn(r, r.X, y, Pad(kv[0], 8, AlignLeft), m.Theme.JSONKey)
		b.DrawTextIn(r, x+1, y, kv[1], m.Theme.Base)
		y++
	}
}

// limitText renders a cgroup limit, or "unlimited" for the zero that a host
// with no delegated controllers reports.
func limitText(v uint64) string {
	if v == 0 {
		return "unlimited"
	}
	return HumanBytes(v)
}

// renderInspect draws the container record as pretty JSON, with the engine's
// create-time warnings above it.
func (m *Model) renderInspect(b Buffer, r Rect, c types.Container) {
	y := r.Y
	if warns := m.warningsFor(c); len(warns) > 0 {
		for _, w := range warns {
			for _, line := range wrapLines("! "+w, r.W) {
				if y >= r.Bottom() {
					return
				}
				b.DrawTextIn(r, r.X, y, line, m.Theme.Warn)
				y++
			}
		}
		if y < r.Bottom() {
			y++
		}
	}
	lines := m.inspectText
	if m.inspectID != c.ID || len(lines) == 0 {
		b.DrawTextIn(r, r.X, y, "inspecting...", m.Theme.Dim)
		return
	}
	off := clampInt(m.scroll[TabInspect], 0, max(len(lines)-1, 0))
	for i := off; i < len(lines) && y < r.Bottom(); i++ {
		style := m.Theme.JSONValue
		trimmed := strings.TrimSpace(lines[i])
		if idx := strings.Index(trimmed, "\": "); idx > 0 {
			style = m.Theme.JSONKey
		}
		b.DrawTextIn(r, r.X, y, lines[i], style)
		y++
	}
}

// renderPorts draws the published port map and the container's addresses.
func (m *Model) renderPorts(b Buffer, r Rect, c types.Container) {
	y := r.Y
	ports := PortStrings(c)
	if len(ports) == 0 {
		b.DrawTextIn(r, r.X, y, "no published or exposed ports", m.Theme.Dim)
		y++
	}
	for _, p := range ports {
		if y >= r.Bottom() {
			return
		}
		b.DrawTextIn(r, r.X, y, p, m.Theme.Base)
		y++
	}
	if y+1 >= r.Bottom() {
		return
	}
	y++
	names := make([]string, 0, len(c.NetworkSettings.Networks))
	for name := range c.NetworkSettings.Networks {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		if y >= r.Bottom() {
			return
		}
		ep := c.NetworkSettings.Networks[name]
		line := ep.IPAddress
		if line == "" {
			line = "(no address)"
		}
		if ep.MacAddress != "" {
			line += "  " + ep.MacAddress
		}
		if ep.HostIfname != "" {
			line += "  " + ep.HostIfname
		}
		x := b.DrawTextIn(r, r.X, y, Pad(name, 12, AlignLeft), m.Theme.JSONKey)
		b.DrawTextIn(r, x+1, y, line, m.Theme.Base)
		y++
	}
}

// renderEvents draws the event strip, newest at the bottom.
func (m *Model) renderEvents(b Buffer, r Rect) {
	if r.Empty() {
		return
	}
	PaneTitle(b, Rect{X: r.X, Y: r.Y, W: r.W, H: 1}, "events", "",
		m.Theme.PaneTitle, m.Theme.Rule)
	body := Rect{X: r.X, Y: r.Y + 1, W: r.W, H: r.H - 1}
	if body.Empty() {
		return
	}
	events := m.events.slice()
	if len(events) == 0 {
		b.DrawTextIn(body, body.X, body.Y, "waiting for events...", m.Theme.Dim)
		return
	}
	start := max(len(events)-body.H, 0)
	for i, e := range events[start:] {
		style := m.Theme.Event
		switch e.Action {
		case "die", "oom", "kill", "destroy":
			style = m.Theme.Error.Without(AttrBold)
		case "start", "create":
			style = m.Theme.Running
		case "pause", "stop":
			style = m.Theme.Warn
		}
		b.DrawTextIn(body, body.X, body.Y+i, EventLine(e, nil), style)
	}
}

// renderStatus draws the status bar: what engine this is, what it is running,
// how much room is left on the data root, and how many host warnings there
// are. The filter prompt takes the bar over while it is open.
func (m *Model) renderStatus(b Buffer, r Rect) {
	if r.Empty() {
		return
	}
	b.Fill(r, Cell{Rune: ' ', Style: m.Theme.Status})

	if m.mode == ModeFilter {
		prompt := "/" + m.filter + "█"
		b.DrawTextIn(r, r.X, r.Y, prompt, m.Theme.Status.With(AttrBold))
		hint := "enter accepts, esc cancels"
		if start := r.Right() - len([]rune(hint)) - 1; start > len([]rune(prompt))+1 {
			b.DrawTextIn(r, start, r.Y, hint, m.Theme.Status)
		}
		return
	}

	version := m.info.Version
	if version == "" {
		version = "?"
	}
	parts := []string{"hull " + version}
	counts := strconv.Itoa(m.info.ContainersRunning) + " up"
	if m.info.ContainersPaused > 0 {
		counts += " " + strconv.Itoa(m.info.ContainersPaused) + " paused"
	}
	counts += " " + strconv.Itoa(m.info.ContainersStopped) + " stopped"
	parts = append(parts, counts)
	if !m.lay.Narrow {
		if m.disk.Known() {
			parts = append(parts, HumanBytes(m.disk.Free)+" free on "+m.disk.Path)
		} else if m.info.DataRoot != "" {
			parts = append(parts, m.info.DataRoot)
		}
		if m.info.Runtime != "" {
			rt := m.info.Runtime
			if m.info.OCIVersion != "" {
				rt += " oci " + m.info.OCIVersion
			}
			parts = append(parts, rt)
		}
	}

	x := b.DrawTextIn(r, r.X, r.Y, " "+strings.Join(parts, "  ·  "), m.Theme.Status)

	// The right-hand end carries the warning count and the help hint, and a
	// live toast takes precedence over both because it is the answer to
	// something the user just did.
	rightParts := []string{}
	if n := len(m.info.Warnings); n > 0 {
		rightParts = append(rightParts, "! "+strconv.Itoa(n)+" warning"+plural(n)+" (w)")
	}
	if !m.info.CgroupV2Delegated && m.info.CgroupVersion != "" {
		rightParts = append(rightParts, "cgroup "+m.info.CgroupVersion)
	}
	rightParts = append(rightParts, "? keys")
	right := strings.Join(rightParts, "  ") + " "
	if start := r.Right() - len([]rune(right)); start > x {
		style := m.Theme.Status
		if len(m.info.Warnings) > 0 {
			style = m.Theme.StatusWarn
		}
		b.DrawTextIn(r, start, r.Y, right, style)
	}

	if toast, ts := m.toastText(); toast != "" {
		ts.Attrs |= AttrReverse
		text := " " + Truncate(toast, max(r.W-2, 1)) + " "
		b.Fill(r, Cell{Rune: ' ', Style: ts})
		b.DrawTextIn(r, r.X, r.Y, text, ts)
	}
}

// plural returns "s" for anything but one.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// renderOverlay draws whichever overlay is up, if any.
func (m *Model) renderOverlay(b Buffer) {
	area := b.Bounds()
	switch m.overlay {
	case overlayHelp:
		helpOverlay(m.Theme, area.W-8).Render(b, area)
	case overlayWarnings:
		lines := []string{}
		if len(m.info.Warnings) == 0 {
			lines = append(lines, "no host warnings - this machine is ready")
		}
		for i, w := range m.info.Warnings {
			if i > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, wrapLines(w, max(area.W-10, 20))...)
		}
		Overlay{
			Title:       "host warnings",
			Lines:       lines,
			Footer:      "any key closes",
			Style:       m.Theme.Warn,
			BorderStyle: m.Theme.OverlayBorder,
			TitleStyle:  m.Theme.OverlayTitle,
		}.Render(b, area)
	case overlayConfirm:
		Overlay{
			Title:       "confirm",
			Lines:       []string{m.confirmText, "", "this cannot be undone"},
			Footer:      "y / n",
			Style:       m.Theme.OverlayText,
			BorderStyle: m.Theme.Error,
			TitleStyle:  m.Theme.Error,
		}.Render(b, area)
	}
}

// sortStrings sorts a slice of strings in place. It is here rather than a sort
// import in the view so the file stays free of anything but drawing.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
