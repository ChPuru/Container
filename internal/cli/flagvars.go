package cli

import (
	"strconv"
	"time"
)

// The *Var forms below complete the FlagSet surface for commands that keep
// their options in one struct rather than in forty separate pointers. They
// are thin wrappers over the value types the flag set already defines, so
// parsing behaviour is identical either way.
//
// Each registers the definition directly rather than going through Var, so the
// value placeholder in help — "int", "decimal", "duration", "list" — matches
// what the same flag would show if it had been declared with the pointer-
// returning form. A user reading "hull run --help" must not be able to tell
// which registration path a flag happened to take.

// Int64Var registers a 64-bit integer flag against an existing variable.
func (f *FlagSet) Int64Var(p *int64, name, short string, def int64, usage string) {
	*p = def
	f.register(&flagDef{
		name: name, short: short, usage: usage,
		value:   (*int64Value)(p),
		def:     strconv.FormatInt(def, 10),
		argName: "int",
	})
}

// Float64Var registers a floating-point flag against an existing variable.
func (f *FlagSet) Float64Var(p *float64, name, short string, def float64, usage string) {
	*p = def
	f.register(&flagDef{
		name: name, short: short, usage: usage,
		value:   (*float64Value)(p),
		def:     strconv.FormatFloat(def, 'g', -1, 64),
		argName: "decimal",
	})
}

// DurationVar registers a duration flag against an existing variable.
func (f *FlagSet) DurationVar(p *time.Duration, name, short string, def time.Duration, usage string) {
	*p = def
	f.register(&flagDef{
		name: name, short: short, usage: usage,
		value:   (*durationValue)(p),
		def:     def.String(),
		argName: "duration",
	})
}

// StringSliceVar registers a repeatable flag against an existing slice.
//
// This is the form a repeated flag needs when its destination lives in a
// struct: taking the pointer that StringSlice returns and dereferencing it at
// registration time would copy the empty default and lose every value the
// parser later appends.
func (f *FlagSet) StringSliceVar(p *[]string, name, short string, usage string) {
	f.register(&flagDef{
		name: name, short: short, usage: usage,
		value:   &stringSliceValue{values: p},
		argName: "list",
	})
}
