package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/rahuldhali/hull/internal/client"
)

// newPullCommand builds "hull pull".
func newPullCommand() *Command {
	var quietFlag, allTags bool
	var platform string
	return &Command{
		Name:    "pull",
		Usage:   "pull [OPTIONS] NAME[:TAG|@DIGEST]",
		Short:   "Download an image from a registry",
		MinArgs: 1,
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&quietFlag, "quiet", "q", false, "Suppress verbose output")
			fs.BoolVar(&allTags, "all-tags", "a", false, "Download all tagged images in the repository")
			fs.StringVar(&platform, "platform", "", "", "Set platform if server is multi-platform capable")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			p := NewProgress(env, quietFlag)
			opts := client.ImagePullOptions{Platform: platform, All: allTags}
			if auth, ok := registryAuthFor(args[0]); ok {
				opts.Auth = auth
			}
			err = cli.ImagePull(ctx, args[0], opts, p.Handle)
			if closeErr := p.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return fmt.Errorf("pull %s: %w", args[0], err)
			}
			env.Println(args[0])
			return nil
		},
	}
}

// newPushCommand builds "hull push".
func newPushCommand() *Command {
	var quietFlag, allTags bool
	return &Command{
		Name:    "push",
		Usage:   "push [OPTIONS] NAME[:TAG]",
		Short:   "Upload an image to a registry",
		MinArgs: 1,
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&quietFlag, "quiet", "q", false, "Suppress verbose output")
			fs.BoolVar(&allTags, "all-tags", "a", false, "Push all tags of the image")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			p := NewProgress(env, quietFlag)
			opts := client.ImagePushOptions{All: allTags}
			if auth, ok := registryAuthFor(args[0]); ok {
				opts.Auth = auth
			}
			err = cli.ImagePush(ctx, args[0], opts, p.Handle)
			if closeErr := p.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return fmt.Errorf("push %s: %w", args[0], err)
			}
			return nil
		},
	}
}

// imageRow is one row of "hull images", and the value a --format template
// sees.
type imageRow struct {
	ID         string            `json:"ID"`
	Repository string            `json:"Repository"`
	Tag        string            `json:"Tag"`
	Digest     string            `json:"Digest,omitempty"`
	CreatedAt  string            `json:"CreatedAt"`
	CreatedSince string          `json:"CreatedSince"`
	Size       string            `json:"Size"`
	Labels     map[string]string `json:"Labels,omitempty"`
}

// newImagesCommand builds "hull images".
func newImagesCommand() *Command {
	var all, quietFlag, noTrunc, digests bool
	var format string
	var filters []string
	return &Command{
		Name:    "images",
		Usage:   "images [OPTIONS] [REPOSITORY[:TAG]]",
		Short:   "List images",
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&all, "all", "a", false, "Show all images (default hides intermediate images)")
			fs.BoolVar(&quietFlag, "quiet", "q", false, "Only show image IDs")
			fs.BoolVar(&noTrunc, "no-trunc", "", false, "Don't truncate output")
			fs.BoolVar(&digests, "digests", "", false, "Show digests")
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
			fs.StringSliceVar(&filters, "filter", "f", "Filter output on conditions provided")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			f, err := buildFilters(filters)
			if err != nil {
				return err
			}
			if len(args) == 1 {
				if f == nil {
					f = client.Filters{}
				}
				f.Add("reference", args[0])
			}
			list, err := cli.ImageList(ctx, client.ImageListOptions{All: all, Filters: f})
			if err != nil {
				return err
			}
			headers := []string{"REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"}
			if digests {
				headers = []string{"REPOSITORY", "TAG", "DIGEST", "IMAGE ID", "CREATED", "SIZE"}
			}
			table := env.newTable(headers...)
			var ids []string
			var items []any
			for _, img := range list {
				for _, row := range imageRows(img, noTrunc) {
					if digests {
						table.Row(row.Repository, row.Tag, row.Digest, row.ID, row.CreatedSince, row.Size)
					} else {
						table.Row(row.Repository, row.Tag, row.ID, row.CreatedSince, row.Size)
					}
					ids = append(ids, row.ID)
					items = append(items, row)
				}
			}
			return env.renderList(quietFlag, format, ids, items, table)
		},
	}
}

// imageRows expands one image into one row per repository tag, which is how
// every image listing has always presented a multiply-tagged image.
func imageRows(img client.ImageSummary, noTrunc bool) []imageRow {
	id := img.ID
	if !noTrunc {
		id = TruncateID(id)
	}
	base := imageRow{
		ID:           id,
		Repository:   "<none>",
		Tag:          "<none>",
		CreatedAt:    img.CreatedAt().Format("2006-01-02 15:04:05 -0700 MST"),
		CreatedSince: HumanSince(img.CreatedAt()),
		Size:         HumanSize(img.Size),
		Labels:       img.Labels,
		Digest:       firstDigest(img.RepoDigests),
	}
	if len(img.RepoTags) == 0 {
		return []imageRow{base}
	}
	rows := make([]imageRow, 0, len(img.RepoTags))
	for _, ref := range img.RepoTags {
		row := base
		row.Repository, row.Tag = splitReference(ref)
		if row.Tag == "" {
			row.Tag = "<none>"
		}
		rows = append(rows, row)
	}
	return rows
}

// firstDigest returns the digest half of the first repo digest, or "<none>".
func firstDigest(digests []string) string {
	for _, d := range digests {
		if _, digest, ok := strings.Cut(d, "@"); ok {
			return digest
		}
	}
	return "<none>"
}

// newImageCommand builds the "hull image" group, which is Docker's noun-first
// spelling of the same verbs.
func newImageCommand() *Command {
	return &Command{
		Name:  "image",
		Usage: "image COMMAND",
		Short: "Manage images",
		Subcommands: []*Command{
			renamed(newImagesCommand(), "ls", "list"),
			renamed(newInspectImageCommand(), "inspect"),
			renamed(newPullCommand(), "pull"),
			renamed(newPushCommand(), "push"),
			renamed(newRemoveImageCommand(), "rm", "remove"),
			renamed(newTagCommand(), "tag"),
			renamed(newSaveCommand(), "save"),
			renamed(newLoadCommand(), "load"),
			renamed(newHistoryCommand(), "history"),
			newImagePruneCommand(),
		},
	}
}

// renamed re-labels a command so the same implementation can appear both as a
// top-level verb and inside a noun group.
func renamed(c *Command, name string, aliases ...string) *Command {
	c.Name = name
	c.Aliases = aliases
	if i := strings.IndexByte(c.Usage, ' '); i > 0 {
		c.Usage = name + c.Usage[i:]
	} else {
		c.Usage = name
	}
	return c
}

// newInspectImageCommand builds "hull image inspect".
func newInspectImageCommand() *Command {
	var format string
	return &Command{
		Name:    "inspect",
		Usage:   "inspect [OPTIONS] IMAGE [IMAGE...]",
		Short:   "Display detailed information on one or more images",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&format, "format", "f", "", "Format output using a Go template or 'json'")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			docs := make([]json.RawMessage, 0, len(args))
			failed := false
			for _, ref := range args {
				raw, err := cli.ImageInspectRaw(ctx, ref)
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

// newImagePruneCommand builds "hull image prune".
func newImagePruneCommand() *Command {
	var all, force bool
	var filters []string
	return &Command{
		Name:    "prune",
		Usage:   "prune [OPTIONS]",
		Short:   "Remove unused images",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&all, "all", "a", false, "Remove all unused images, not just dangling ones")
			fs.BoolVar(&force, "force", "f", false, "Do not prompt for confirmation")
			fs.StringSliceVar(&filters, "filter", "", "Provide filter values (e.g. until=24h)")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			f, err := buildFilters(filters)
			if err != nil {
				return err
			}
			if f == nil {
				f = client.Filters{}
			}
			if all {
				f.Add("dangling", "false")
			}
			if !force {
				ok, err := confirm(env, "This will remove all unused images.")
				if err != nil {
					return err
				}
				if !ok {
					return nil
				}
			}
			report, err := cli.ImagesPrune(ctx, f)
			if err != nil {
				return err
			}
			printPruneReport(env, report)
			return nil
		},
	}
}

// newRemoveImageCommand builds "hull rmi".
func newRemoveImageCommand() *Command {
	var force, noPrune bool
	return &Command{
		Name:    "rmi",
		Usage:   "rmi [OPTIONS] IMAGE [IMAGE...]",
		Short:   "Remove one or more images",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&force, "force", "f", false, "Force removal of the image")
			fs.BoolVar(&noPrune, "no-prune", "", false, "Do not delete untagged parents")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			failed := false
			for _, ref := range args {
				deleted, err := cli.ImageRemove(ctx, ref, force, noPrune)
				if err != nil {
					env.ReportError(err)
					failed = true
					continue
				}
				for _, d := range deleted {
					switch {
					case d.Untagged != "":
						env.Printf("Untagged: %s\n", d.Untagged)
					case d.Deleted != "":
						env.Printf("Deleted: %s\n", d.Deleted)
					}
				}
			}
			if failed {
				return Exit(ExitFailure)
			}
			return nil
		},
	}
}

// newTagCommand builds "hull tag".
func newTagCommand() *Command {
	return &Command{
		Name:    "tag",
		Usage:   "tag SOURCE_IMAGE[:TAG] TARGET_IMAGE[:TAG]",
		Short:   "Create a tag that refers to a source image",
		MinArgs: 2,
		MaxArgs: 2,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			return cli.ImageTag(ctx, args[0], args[1])
		},
	}
}

// newSaveCommand builds "hull save".
func newSaveCommand() *Command {
	var output string
	return &Command{
		Name:    "save",
		Usage:   "save [OPTIONS] IMAGE [IMAGE...]",
		Short:   "Save one or more images to a tar archive",
		MinArgs: 1,
		MaxArgs: -1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&output, "output", "o", "", "Write to a file instead of STDOUT")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			body, err := cli.ImageSave(ctx, args)
			if err != nil {
				return err
			}
			defer func() { _ = body.Close() }()
			return writeArchive(env, output, body, "image archive")
		},
	}
}

// newLoadCommand builds "hull load".
func newLoadCommand() *Command {
	var input string
	var quietFlag bool
	return &Command{
		Name:    "load",
		Usage:   "load [OPTIONS]",
		Short:   "Load an image from a tar archive or STDIN",
		MaxArgs: 0,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&input, "input", "i", "", "Read from a tar archive file instead of STDIN")
			fs.BoolVar(&quietFlag, "quiet", "q", false, "Suppress the load output")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, _ []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			var src io.Reader = env.In
			if input != "" {
				f, err := os.Open(input)
				if err != nil {
					return fmt.Errorf("opening %s: %w", input, err)
				}
				defer func() { _ = f.Close() }()
				src = f
			} else if env.StdinIsTerminal() {
				return Errorf("no archive on stdin: pass -i FILE or redirect one in")
			}
			p := NewProgress(env, quietFlag)
			err = cli.ImageLoad(ctx, src, quietFlag, p.Handle)
			if closeErr := p.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
			if quietFlag && p.AuxID() != "" {
				env.Println(p.AuxID())
			}
			return nil
		},
	}
}

// newHistoryCommand builds "hull history".
func newHistoryCommand() *Command {
	var quietFlag, noTrunc bool
	var format string
	return &Command{
		Name:    "history",
		Usage:   "history [OPTIONS] IMAGE",
		Short:   "Show the history of an image",
		MinArgs: 1,
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&quietFlag, "quiet", "q", false, "Only show image IDs")
			fs.BoolVar(&noTrunc, "no-trunc", "", false, "Don't truncate output")
			fs.StringVar(&format, "format", "", "", "Format output using a Go template or 'json'")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			entries, err := cli.ImageHistory(ctx, args[0])
			if err != nil {
				return err
			}
			table := env.newTable("IMAGE", "CREATED", "CREATED BY", "SIZE", "COMMENT")
			ids := make([]string, 0, len(entries))
			items := make([]any, 0, len(entries))
			for _, e := range entries {
				id := e.ID
				if !noTrunc {
					id = TruncateID(id)
				}
				by := strings.ReplaceAll(e.CreatedBy, "\t", " ")
				if !noTrunc {
					by = Ellipsis(by, 45)
				}
				row := historyRow{
					ID:           id,
					CreatedSince: HumanSince(time.Unix(e.Created, 0)),
					CreatedBy:    by,
					Size:         HumanSize(e.Size),
					Comment:      e.Comment,
				}
				table.Row(row.ID, row.CreatedSince, row.CreatedBy, row.Size, row.Comment)
				ids = append(ids, id)
				items = append(items, row)
			}
			return env.renderList(quietFlag, format, ids, items, table)
		},
	}
}

// historyRow is one row of "hull history".
type historyRow struct {
	ID           string `json:"ID"`
	CreatedSince string `json:"CreatedSince"`
	CreatedBy    string `json:"CreatedBy"`
	Size         string `json:"Size"`
	Comment      string `json:"Comment,omitempty"`
}

// newLoginCommand builds "hull login".
func newLoginCommand() *Command {
	var user, password string
	var passwordStdin bool
	return &Command{
		Name:    "login",
		Usage:   "login [OPTIONS] [SERVER]",
		Short:   "Log in to a registry",
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.StringVar(&user, "username", "u", "", "Registry username")
			fs.StringVar(&password, "password", "p", "", "Registry password")
			fs.BoolVar(&passwordStdin, "password-stdin", "", false, "Take the password from stdin")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			server := "https://index.docker.io/v1/"
			if len(args) == 1 {
				server = args[0]
			}
			if passwordStdin {
				if password != "" {
					return Errorf("conflicting options: --password and --password-stdin")
				}
				buf, err := io.ReadAll(io.LimitReader(env.In, 1<<16))
				if err != nil {
					return fmt.Errorf("reading password from stdin: %w", err)
				}
				password = strings.TrimRight(string(buf), "\r\n")
			}
			if user == "" {
				if !env.StdinIsTerminal() {
					return Errorf("a username is required: pass -u")
				}
				env.Printf("Username: ")
				if _, err := fmt.Fscanln(env.In, &user); err != nil {
					return fmt.Errorf("reading username: %w", err)
				}
			}
			if password == "" {
				if !env.StdinIsTerminal() {
					return Errorf("a password is required: pass --password-stdin")
				}
				env.Printf("Password: ")
				secret, err := term.ReadPassword(int(env.In.Fd()))
				env.Println("")
				if err != nil {
					return fmt.Errorf("reading password: %w", err)
				}
				password = string(secret)
			}
			res, err := cli.RegistryLogin(ctx, client.AuthConfig{
				Username:      user,
				Password:      password,
				ServerAddress: server,
			})
			if err != nil {
				return err
			}
			if res.Status != "" {
				env.Println(res.Status)
			} else {
				env.Println("Login Succeeded")
			}
			return nil
		},
	}
}

// newLogoutCommand builds "hull logout".
//
// Credentials live in the engine, where the pulls happen, so logging out is a
// login with empty credentials rather than a local file edit.
func newLogoutCommand() *Command {
	return &Command{
		Name:    "logout",
		Usage:   "logout [SERVER]",
		Short:   "Log out from a registry",
		MaxArgs: 1,
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			server := "https://index.docker.io/v1/"
			if len(args) == 1 {
				server = args[0]
			}
			if _, err := cli.RegistryLogin(ctx, client.AuthConfig{ServerAddress: server}); err != nil {
				if !client.IsUnauthorized(err) {
					return err
				}
			}
			env.Printf("Removing login credentials for %s\n", server)
			return nil
		},
	}
}
