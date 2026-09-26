// Package cli implements hull's command-line interface: the command tree
// described in docs/CLI.md, its flag parser, and the output discipline that
// keeps a pipe free of colour, spinners and progress bars.
//
// The flag parser is hull's own, built on the stdlib [flag.Value] interface so
// custom values stay conventional, because the stdlib parser cannot express
// three things hull's users expect from Docker's spelling: combined short
// flags (-it), repeatable flags (-e A=1 -e B=2) and a stop at the first
// operand so "hull run -it alpine sh -c ..." does not eat the container's own
// flags.
package cli

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrHelp is returned by [FlagSet.Parse] when -h or --help is present. It is
// the stdlib's sentinel so callers may compare against either package.
var ErrHelp = flag.ErrHelp

// Value is the interface a custom flag value implements; it is [flag.Value].
type Value = flag.Value

// BoolValue is implemented by a [Value] that takes no argument, so the parser
// knows -it may be a cluster of two booleans rather than a flag and its value.
type BoolValue interface {
	Value
	// IsBoolFlag reports that the flag stands alone.
	IsBoolFlag() bool
}

// flagDef is one registered flag.
type flagDef struct {
	name    string
	short   string
	usage   string
	value   Value
	def     string
	isBool  bool
	changed bool
	hidden  bool
	// argName labels the value in help text, e.g. "list" in "-e list".
	argName string
}

// FlagSet holds one command's flags and the operands left after parsing.
type FlagSet struct {
	name    string
	defs    []*flagDef
	byLong  map[string]*flagDef
	byShort map[string]*flagDef
	args    []string
	// stopAtOperand ends flag parsing at the first non-flag argument.
	stopAtOperand bool
	// helpRequested records that -h or --help was seen.
	helpRequested bool
	out           io.Writer
}

// NewFlagSet builds an empty flag set named for its command.
func NewFlagSet(name string) *FlagSet {
	return &FlagSet{
		name:    name,
		byLong:  map[string]*flagDef{},
		byShort: map[string]*flagDef{},
	}
}

// SetOutput redirects help and error text.
func (f *FlagSet) SetOutput(w io.Writer) { f.out = w }

// StopAtOperand makes parsing end at the first argument that is not a flag,
// leaving it and everything after it in Args. Commands that pass a command
// line through to a container need this.
func (f *FlagSet) StopAtOperand(v bool) { f.stopAtOperand = v }

// Args returns the operands left after parsing.
func (f *FlagSet) Args() []string { return f.args }

// Arg returns the i'th operand, or "" when there is none.
func (f *FlagSet) Arg(i int) string {
	if i < 0 || i >= len(f.args) {
		return ""
	}
	return f.args[i]
}

// NArg returns the number of operands.
func (f *FlagSet) NArg() int { return len(f.args) }

// Changed reports whether a flag was set on the command line, which is how a
// command tells "left at its default" from "explicitly set to the default".
func (f *FlagSet) Changed(name string) bool {
	if d, ok := f.byLong[name]; ok {
		return d.changed
	}
	return false
}

// Lookup returns the value of a registered flag by long name.
func (f *FlagSet) Lookup(name string) Value {
	if d, ok := f.byLong[name]; ok {
		return d.value
	}
	return nil
}

// HelpRequested reports whether -h or --help was parsed.
func (f *FlagSet) HelpRequested() bool { return f.helpRequested }

// register adds a definition, panicking on a duplicate because that is a
// programming error in the command tree, not a user error.
func (f *FlagSet) register(d *flagDef) {
	if d.name != "" {
		if _, dup := f.byLong[d.name]; dup {
			panic("cli: duplicate flag --" + d.name + " on " + f.name)
		}
		f.byLong[d.name] = d
	}
	if d.short != "" {
		if _, dup := f.byShort[d.short]; dup {
			panic("cli: duplicate flag -" + d.short + " on " + f.name)
		}
		f.byShort[d.short] = d
	}
	f.defs = append(f.defs, d)
}

// Var registers a custom value.
func (f *FlagSet) Var(value Value, name, short, usage string) {
	_, isBool := value.(BoolValue)
	f.register(&flagDef{name: name, short: short, usage: usage, value: value, def: value.String(), isBool: isBool})
}

// Hide marks a registered flag as undocumented.
func (f *FlagSet) Hide(name string) {
	if d, ok := f.byLong[name]; ok {
		d.hidden = true
	}
}

// ---------- value types ----------

// boolValue is a bool flag.
type boolValue bool

// Set parses a bool.
func (b *boolValue) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return fmt.Errorf("invalid boolean %q", s)
	}
	*b = boolValue(v)
	return nil
}

// String renders the bool.
func (b *boolValue) String() string { return strconv.FormatBool(bool(*b)) }

// IsBoolFlag marks this value as standing alone.
func (b *boolValue) IsBoolFlag() bool { return true }

// Bool registers a bool flag and returns a pointer to its value.
func (f *FlagSet) Bool(name, short string, def bool, usage string) *bool {
	p := new(bool)
	*p = def
	f.BoolVar(p, name, short, def, usage)
	return p
}

// BoolVar registers a bool flag bound to p.
func (f *FlagSet) BoolVar(p *bool, name, short string, def bool, usage string) {
	*p = def
	f.register(&flagDef{name: name, short: short, usage: usage, value: (*boolValue)(p), def: strconv.FormatBool(def), isBool: true})
}

// stringValue is a string flag.
type stringValue string

// Set stores the string verbatim.
func (s *stringValue) Set(v string) error { *s = stringValue(v); return nil }

// String returns the value.
func (s *stringValue) String() string { return string(*s) }

// String registers a string flag.
func (f *FlagSet) String(name, short, def, usage string) *string {
	p := new(string)
	f.StringVar(p, name, short, def, usage)
	return p
}

// StringVar registers a string flag bound to p.
func (f *FlagSet) StringVar(p *string, name, short, def, usage string) {
	*p = def
	f.register(&flagDef{name: name, short: short, usage: usage, value: (*stringValue)(p), def: def, argName: "string"})
}

// intValue is an int flag.
type intValue int

// Set parses an integer.
func (i *intValue) Set(s string) error {
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid integer %q", s)
	}
	*i = intValue(v)
	return nil
}

// String renders the integer.
func (i *intValue) String() string { return strconv.Itoa(int(*i)) }

// Int registers an int flag.
func (f *FlagSet) Int(name, short string, def int, usage string) *int {
	p := new(int)
	f.IntVar(p, name, short, def, usage)
	return p
}

// IntVar registers an int flag bound to p.
func (f *FlagSet) IntVar(p *int, name, short string, def int, usage string) {
	*p = def
	f.register(&flagDef{name: name, short: short, usage: usage, value: (*intValue)(p), def: strconv.Itoa(def), argName: "int"})
}

// int64Value is an int64 flag.
type int64Value int64

// Set parses a 64-bit integer.
func (i *int64Value) Set(s string) error {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid integer %q", s)
	}
	*i = int64Value(v)
	return nil
}

// String renders the integer.
func (i *int64Value) String() string { return strconv.FormatInt(int64(*i), 10) }

// Int64 registers an int64 flag.
func (f *FlagSet) Int64(name, short string, def int64, usage string) *int64 {
	p := new(int64)
	*p = def
	f.register(&flagDef{name: name, short: short, usage: usage, value: (*int64Value)(p), def: strconv.FormatInt(def, 10), argName: "int"})
	return p
}

// float64Value is a float flag, used by --cpus.
type float64Value float64

// Set parses a float.
func (v *float64Value) Set(s string) error {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("invalid number %q", s)
	}
	*v = float64Value(f)
	return nil
}

// String renders the float without trailing zeros.
func (v *float64Value) String() string { return strconv.FormatFloat(float64(*v), 'g', -1, 64) }

// Float64 registers a float flag.
func (f *FlagSet) Float64(name, short string, def float64, usage string) *float64 {
	p := new(float64)
	*p = def
	f.register(&flagDef{name: name, short: short, usage: usage, value: (*float64Value)(p), def: strconv.FormatFloat(def, 'g', -1, 64), argName: "decimal"})
	return p
}

// durationValue is a duration flag.
type durationValue time.Duration

// Set parses a Go duration.
func (d *durationValue) Set(s string) error {
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	*d = durationValue(v)
	return nil
}

// String renders the duration.
func (d *durationValue) String() string { return time.Duration(*d).String() }

// Duration registers a duration flag.
func (f *FlagSet) Duration(name, short string, def time.Duration, usage string) *time.Duration {
	p := new(time.Duration)
	*p = def
	f.register(&flagDef{name: name, short: short, usage: usage, value: (*durationValue)(p), def: def.String(), argName: "duration"})
	return p
}

// stringSliceValue accumulates repeated occurrences of one flag.
type stringSliceValue struct {
	values   *[]string
	replaced bool
}

// Set appends one occurrence, discarding the compiled-in default on the first
// one so a default list does not silently survive an explicit setting.
func (s *stringSliceValue) Set(v string) error {
	if !s.replaced {
		*s.values = nil
		s.replaced = true
	}
	*s.values = append(*s.values, v)
	return nil
}

// String renders the accumulated list.
func (s *stringSliceValue) String() string {
	if s.values == nil {
		return ""
	}
	return strings.Join(*s.values, ",")
}

// StringSlice registers a repeatable flag and returns a pointer to the slice
// it accumulates into.
func (f *FlagSet) StringSlice(name, short string, def []string, usage string) *[]string {
	p := new([]string)
	*p = append(*p, def...)
	f.register(&flagDef{
		name: name, short: short, usage: usage,
		value:   &stringSliceValue{values: p},
		def:     strings.Join(def, ","),
		argName: "list",
	})
	return p
}

// ---------- parsing ----------

// parseError is a user-facing flag error.
type parseError struct{ msg string }

// Error implements the error interface.
func (e *parseError) Error() string { return e.msg }

// errf builds a parse error.
func errf(format string, args ...any) error { return &parseError{msg: fmt.Sprintf(format, args...)} }

// Parse consumes args, which must not include the command name.
//
// It understands --flag, --flag=value, --flag value, -f, -fvalue, -f value,
// clustered short booleans (-it), a repeated flag, and -- to end flag parsing.
// A lone "-" is an operand, by the usual stdin convention.
func (f *FlagSet) Parse(args []string) error {
	f.args = nil
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			f.args = append(f.args, args[i+1:]...)
			return nil
		case arg == "-" || !strings.HasPrefix(arg, "-"):
			f.args = append(f.args, arg)
			if f.stopAtOperand {
				f.args = append(f.args, args[i+1:]...)
				return nil
			}
		case strings.HasPrefix(arg, "--"):
			used, err := f.parseLong(arg[2:], args[i+1:])
			if err != nil {
				return err
			}
			i += used
		default:
			used, err := f.parseShortCluster(arg[1:], args[i+1:])
			if err != nil {
				return err
			}
			i += used
		}
	}
	return nil
}

// parseLong handles one --name[=value] token and reports how many following
// arguments it consumed.
func (f *FlagSet) parseLong(token string, rest []string) (int, error) {
	name, value, hasValue := strings.Cut(token, "=")
	if name == "help" {
		f.helpRequested = true
		return 0, ErrHelp
	}
	d, ok := f.byLong[name]
	if !ok {
		return 0, errf("unknown flag: --%s", name)
	}
	if d.isBool && !hasValue {
		value, hasValue = "true", true
	}
	if !hasValue {
		if len(rest) == 0 {
			return 0, errf("flag needs an argument: --%s", name)
		}
		return 1, f.set(d, rest[0], "--"+name)
	}
	return 0, f.set(d, value, "--"+name)
}

// parseShortCluster handles one -abc token and reports how many following
// arguments it consumed.
func (f *FlagSet) parseShortCluster(token string, rest []string) (int, error) {
	for i := 0; i < len(token); i++ {
		short := string(token[i])
		if short == "h" {
			if _, defined := f.byShort["h"]; !defined {
				f.helpRequested = true
				return 0, ErrHelp
			}
		}
		d, ok := f.byShort[short]
		if !ok {
			return 0, errf("unknown shorthand flag: %q in -%s", short, token)
		}
		if d.isBool {
			// A trailing "=false" disambiguates an explicit negation.
			if i+1 < len(token) && token[i+1] == '=' {
				return 0, f.set(d, token[i+2:], "-"+short)
			}
			if err := f.set(d, "true", "-"+short); err != nil {
				return 0, err
			}
			continue
		}
		// The rest of the cluster is this flag's value, if there is any.
		if i+1 < len(token) {
			value := token[i+1:]
			value = strings.TrimPrefix(value, "=")
			return 0, f.set(d, value, "-"+short)
		}
		if len(rest) == 0 {
			return 0, errf("flag needs an argument: -%s", short)
		}
		return 1, f.set(d, rest[0], "-"+short)
	}
	return 0, nil
}

// set applies one value and records that the flag was touched.
func (f *FlagSet) set(d *flagDef, value, as string) error {
	if err := d.value.Set(value); err != nil {
		return errf("invalid argument %q for %s: %v", value, as, err)
	}
	d.changed = true
	return nil
}

// ---------- help ----------

// FlagUsage renders the flag block of a command's help, aligned and sorted by
// long name, with short forms shown alongside.
func (f *FlagSet) FlagUsage() string {
	type row struct{ left, right string }
	var rows []row
	width := 0
	defs := make([]*flagDef, 0, len(f.defs))
	for _, d := range f.defs {
		if !d.hidden {
			defs = append(defs, d)
		}
	}
	sort.SliceStable(defs, func(i, j int) bool { return defs[i].name < defs[j].name })
	for _, d := range defs {
		var b strings.Builder
		if d.short != "" {
			b.WriteString("-" + d.short)
			if d.name != "" {
				b.WriteString(", ")
			}
		} else {
			b.WriteString("    ")
		}
		if d.name != "" {
			b.WriteString("--" + d.name)
		}
		if !d.isBool && d.argName != "" {
			b.WriteString(" " + d.argName)
		}
		usage := d.usage
		if d.def != "" && d.def != "false" && d.def != "0" && d.def != "0s" {
			usage += " (default " + d.def + ")"
		}
		left := b.String()
		if len(left) > width {
			width = len(left)
		}
		rows = append(rows, row{left: left, right: usage})
	}
	var out strings.Builder
	for _, r := range rows {
		out.WriteString("  " + r.left + strings.Repeat(" ", width-len(r.left)) + "   " + r.right + "\n")
	}
	return out.String()
}
