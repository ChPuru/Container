package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rahuldhali/hull/internal/client"
)

// objectKinds are the object kinds "hull inspect" can resolve, in the order it
// tries them. Containers come first because that is what a user almost always
// means, and a name that is both a container and an image must resolve the
// same way Docker resolves it.
var objectKinds = []string{"container", "image", "network", "volume"}

// newInspectCommand builds "hull inspect".
func newInspectCommand() *Command {
	var format, kind string
	var size bool
	return &Command{
		Name:  "inspect",
		Usage: "inspect [OPTIONS] NAME|ID [NAME|ID...]",
		Short: "Return low-level information on hull objects",
		Long: "Return low-level information on containers, images, networks and volumes.\n\n" +
			"The default output is a JSON array, so piping into jq always works.\n" +
			"--format takes a Go template, and --format json is the same array.",
		Example: "  hull inspect web\n" +
			"  hull inspect --format '{{.State.Status}}' web\n" +
			"  hull inspect --type image alpine:3.20",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&format, "format", "f", "", "Format output using a Go template or 'json'")
			fs.StringVar(&kind, "type", "", "", `Restrict the search to one kind ("container", "image", "network", "volume")`)
			fs.BoolVar(&size, "size", "s", false, "Display total file sizes if the type is container")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			kinds := objectKinds
			if kind != "" {
				if !containsString(objectKinds, kind) {
					return Errorf("invalid --type %q: want container, image, network or volume", kind)
				}
				kinds = []string{kind}
			}
			var docs []json.RawMessage
			failed := false
			for _, name := range args {
				raw, err := inspectOne(ctx, cli, kinds, name, size)
				if err != nil {
					env.ReportError(err)
					failed = true
					continue
				}
				docs = append(docs, raw)
			}
			if err := writeInspect(env, format, docs); err != nil {
				return err
			}
			if failed {
				return Exit(ExitFailure)
			}
			return nil
		},
	}
}

// inspectOne resolves one name against each kind in turn and returns the raw
// JSON the engine sent, so no field is lost to a struct hull has not modelled.
func inspectOne(ctx context.Context, cli *client.Client, kinds []string, name string, size bool) (json.RawMessage, error) {
	var lastErr error
	for _, k := range kinds {
		var (
			raw json.RawMessage
			err error
		)
		switch k {
		case "container":
			raw, err = cli.ContainerInspectRaw(ctx, name, size)
		case "image":
			raw, err = cli.ImageInspectRaw(ctx, name)
		case "network":
			var n *client.NetworkResource
			n, err = cli.NetworkInspect(ctx, name, false)
			if err == nil {
				raw, err = marshalRaw(n)
			}
		case "volume":
			var v *client.Volume
			v, err = cli.VolumeInspect(ctx, name)
			if err == nil {
				raw, err = marshalRaw(v)
			}
		}
		if err == nil {
			return raw, nil
		}
		if !client.IsNotFound(err) {
			return nil, err
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, Errorf("no such object: %s", name)
	}
	return nil, Errorf("no such object: %s", name)
}

// marshalRaw re-encodes a decoded object so every kind reaches the formatter
// in the same shape.
func marshalRaw(v any) (json.RawMessage, error) {
	buf, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encoding inspect result: %w", err)
	}
	return json.RawMessage(buf), nil
}

// writeInspect renders the collected documents, either as one JSON array or
// through a template applied to each.
func writeInspect(env *Env, format string, docs []json.RawMessage) error {
	if format == "" || format == FormatJSON {
		if docs == nil {
			docs = []json.RawMessage{}
		}
		return WriteJSON(env.Out, docs)
	}
	t, err := NewTemplate(format)
	if err != nil {
		return err
	}
	items := make([]any, 0, len(docs))
	for _, d := range docs {
		var v any
		if err := json.Unmarshal(d, &v); err != nil {
			return fmt.Errorf("decoding inspect result: %w", err)
		}
		items = append(items, v)
	}
	return RenderTemplate(env.Out, t, items)
}

// containsString reports whether s is in list.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
