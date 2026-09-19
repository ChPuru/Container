package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/template"
)

// FormatJSON is the --format value that asks for a JSON array instead of a
// template or a table.
const FormatJSON = "json"

// Table renders aligned columns, sized to the terminal when there is one.
//
// Columns are measured from their content. When the total exceeds Width the
// widest column is shrunk — never below a legible minimum — and its cells are
// ellipsised. Width of zero means "do not truncate", which is what a non-TTY
// stdout gets, so piping into a script is lossless.
type Table struct {
	// Width is the terminal width to fit into, or zero for unlimited.
	Width int
	// MinColumn is the narrowest a column may be shrunk to.
	MinColumn int
	// Gap is the spacing between columns.
	Gap int

	headers []string
	rows    [][]string
}

// NewTable starts a table with the given headers.
func NewTable(headers ...string) *Table {
	return &Table{MinColumn: 6, Gap: 3, headers: headers}
}

// Row appends one row. Missing cells render empty, extra cells are dropped,
// so a caller cannot knock the columns out of alignment.
func (t *Table) Row(cells ...string) {
	row := make([]string, len(t.headers))
	copy(row, cells)
	t.rows = append(t.rows, row)
}

// Len reports how many data rows the table holds.
func (t *Table) Len() int { return len(t.rows) }

// Render writes the table, header first.
func (t *Table) Render(w io.Writer) error {
	widths := t.columnWidths()
	var b strings.Builder
	writeRow := func(cells []string) {
		last := len(cells) - 1
		for i, cell := range cells {
			cell = Ellipsis(cell, widths[i])
			b.WriteString(cell)
			if i == last {
				break
			}
			pad := widths[i] - runeLen(cell) + t.gap()
			if pad < 1 {
				pad = 1
			}
			b.WriteString(strings.Repeat(" ", pad))
		}
		b.WriteByte('\n')
	}
	if len(t.headers) > 0 {
		writeRow(t.headers)
	}
	for _, row := range t.rows {
		writeRow(row)
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write table: %w", err)
	}
	return nil
}

// gap returns the column spacing, defaulting when the caller left it zero.
func (t *Table) gap() int {
	if t.Gap <= 0 {
		return 3
	}
	return t.Gap
}

// minColumn returns the shrink floor, defaulting when the caller left it zero.
func (t *Table) minColumn() int {
	if t.MinColumn <= 0 {
		return 6
	}
	return t.MinColumn
}

// columnWidths measures every column and shrinks the widest ones until the
// table fits the terminal.
func (t *Table) columnWidths() []int {
	widths := make([]int, len(t.headers))
	for i, h := range t.headers {
		widths[i] = runeLen(h)
	}
	for _, row := range t.rows {
		for i, cell := range row {
			if i < len(widths) && runeLen(cell) > widths[i] {
				widths[i] = runeLen(cell)
			}
		}
	}
	if t.Width <= 0 || len(widths) == 0 {
		return widths
	}
	total := func() int {
		n := t.gap() * (len(widths) - 1)
		for _, w := range widths {
			n += w
		}
		return n
	}
	for total() > t.Width {
		widest, idx := 0, -1
		for i, w := range widths {
			if w > widest && w > t.minColumn() {
				widest, idx = w, i
			}
		}
		if idx < 0 {
			break
		}
		widths[idx]--
	}
	return widths
}

// runeLen counts a cell's width in runes, which is close enough for the
// identifiers, names and sizes these tables hold.
func runeLen(s string) int { return len([]rune(s)) }

// WriteJSON writes any value as an indented JSON document. Every listing
// command's "--format json" goes through here, so the shape is one array
// rather than a stream of objects.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

// NewTemplate compiles a --format value into a template.
//
// A leading "table " is accepted and stripped, because Docker's own format
// strings are written that way and a user pasting one should not get a parse
// error. Literal \t and \n that a shell has left alone are expanded, since
// they are the whole point of a custom format.
func NewTemplate(format string) (*template.Template, error) {
	body := strings.TrimPrefix(format, "table ")
	body = expandEscapes(body)
	t, err := template.New("format").Funcs(TemplateFuncs()).Parse(body)
	if err != nil {
		return nil, fmt.Errorf("invalid --format %q: %w", format, err)
	}
	return t, nil
}

// RenderTemplate executes a compiled --format template once per item,
// guaranteeing a newline after each so the output is line-oriented.
func RenderTemplate(w io.Writer, t *template.Template, items []any) error {
	for _, item := range items {
		var b strings.Builder
		if err := t.Execute(&b, item); err != nil {
			return fmt.Errorf("apply --format: %w", err)
		}
		out := b.String()
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		if _, err := io.WriteString(w, out); err != nil {
			return fmt.Errorf("write formatted output: %w", err)
		}
	}
	return nil
}

// expandEscapes turns the literal \t and \n a shell leaves in a --format
// value into real characters.
func expandEscapes(s string) string {
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, `\n`, "\n")
	return s
}

// TemplateFuncs are the helpers available inside a --format template: the
// subset of Docker's that people actually use, plus hull's own humanisers so
// a custom format can render a size or an age exactly as the default layout
// does.
func TemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"json": func(v any) (string, error) {
			buf, err := json.Marshal(v)
			if err != nil {
				return "", fmt.Errorf("json: %w", err)
			}
			return string(buf), nil
		},
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"title": func(s string) string {
			if s == "" {
				return s
			}
			return strings.ToUpper(s[:1]) + s[1:]
		},
		"join":     func(sep string, v []string) string { return strings.Join(v, sep) },
		"split":    func(sep, s string) []string { return strings.Split(s, sep) },
		"truncate": Ellipsis,
		"shortID":  TruncateID,
		"size":     HumanSize,
		"duration": HumanDuration,
		"since":    HumanSince,
		"pad": func(width int, s string) string {
			if runeLen(s) >= width {
				return s
			}
			return s + strings.Repeat(" ", width-runeLen(s))
		},
	}
}
