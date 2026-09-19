package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/rahuldhali/hull/internal/client"
)

// newCopyCommand builds "hull cp", which moves files between the host and a
// container in either direction through the archive endpoints.
func newCopyCommand() *Command {
	var archiveMode, followLink, quietFlag bool
	return &Command{
		Name:  "cp",
		Usage: "cp [OPTIONS] SRC_PATH|CONTAINER:SRC_PATH DEST_PATH|CONTAINER:DEST_PATH",
		Short: "Copy files or folders between a container and the local filesystem",
		Long: "Copy files or folders between a container and the local filesystem.\n\n" +
			"Exactly one side must name a container. A Windows path keeps its drive\n" +
			"letter: \"C:\\src\" is a host path, not a container called C.\n" +
			"Use \"-\" as the host side to read or write a tar stream on stdin or stdout.",
		Example: "  hull cp ./site web:/usr/share/nginx/html\n" +
			"  hull cp web:/etc/nginx/nginx.conf ./nginx.conf",
		MinArgs: 2,
		MaxArgs: 2,
		Flags: func(fs *FlagSet) {
			fs.BoolVar(&archiveMode, "archive", "a", false, "Preserve uid/gid of the copied files")
			fs.BoolVar(&followLink, "follow-link", "L", false, "Always follow a symlink in SRC_PATH")
			fs.BoolVar(&quietFlag, "quiet", "q", false, "Suppress progress output")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			srcCtr, srcPath := splitCopyArg(args[0])
			dstCtr, dstPath := splitCopyArg(args[1])
			switch {
			case srcCtr == "" && dstCtr == "":
				return Errorf("one side of the copy must be a container, as CONTAINER:PATH")
			case srcCtr != "" && dstCtr != "":
				return Errorf("copying between two containers is not supported")
			}
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			if srcCtr != "" {
				return copyFromContainer(ctx, env, cli, srcCtr, srcPath, dstPath, followLink)
			}
			return copyToContainer(ctx, env, cli, srcPath, dstCtr, dstPath, client.CopyToContainerOptions{
				CopyUIDGID: archiveMode,
			}, followLink)
		},
	}
}

// splitCopyArg separates a "container:path" argument from a plain host path.
//
// A Windows drive letter is the hard case: "C:\src" has a colon in exactly the
// place the container separator goes, so a single-character prefix is always
// read as a drive, never as a container name. Container names are longer than
// one character everywhere it matters.
func splitCopyArg(arg string) (container, p string) {
	if arg == "-" {
		return "", arg
	}
	i := strings.Index(arg, ":")
	if i <= 0 {
		return "", arg
	}
	if i == 1 && isDriveLetter(arg[0]) {
		return "", arg
	}
	if strings.ContainsAny(arg[:i], `\/`) {
		return "", arg
	}
	return arg[:i], arg[i+1:]
}

// copyFromContainer streams a path out of a container and unpacks it on the
// host, or writes the raw tar to stdout when the destination is "-".
func copyFromContainer(ctx context.Context, env *Env, cli *client.Client, container, srcPath, dst string, followLink bool) error {
	body, stat, err := cli.CopyFromContainer(ctx, container, srcPath)
	if err != nil {
		return err
	}

	// -L means "copy what the link points at", in both directions. The stat
	// tells us the path was a symlink; re-issuing the copy against its target
	// is what actually follows it. Without this the flag silently did nothing
	// on the container-to-host direction and copied the link itself.
	if followLink && stat.LinkTarget != "" {
		target := stat.LinkTarget
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(srcPath), target)
		}
		env.Debugf("following symlink %s -> %s", srcPath, target)
		_ = body.Close()
		if body, stat, err = cli.CopyFromContainer(ctx, container, target); err != nil {
			return fmt.Errorf("following symlink %s to %s: %w", srcPath, target, err)
		}
	}
	defer func() { _ = body.Close() }()

	if dst == "-" {
		if _, err := io.Copy(env.Out, body); err != nil {
			return fmt.Errorf("writing archive: %w", err)
		}
		return nil
	}

	dst = TranslateLocalPath(dst)
	target, rename, err := resolveHostDestination(dst, stat)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", target, err)
	}
	env.Debugf("extracting %s from %s into %s", srcPath, container, target)
	return untarTo(body, target, rename)
}

// resolveHostDestination decides where an extracted archive should land and
// whether its top-level entry needs renaming.
//
// The rules are Docker's: copying a directory into an existing directory puts
// it inside; copying into a path that does not exist creates it under that
// name; copying a file onto an existing file overwrites it.
func resolveHostDestination(dst string, stat client.PathStat) (target, rename string, err error) {
	info, statErr := os.Stat(dst)
	switch {
	case statErr == nil && info.IsDir():
		return dst, "", nil
	case statErr == nil:
		// An existing file: replace it, keeping its name.
		return filepath.Dir(dst), filepath.Base(dst), nil
	case os.IsNotExist(statErr):
		parent := filepath.Dir(dst)
		if _, err := os.Stat(parent); err != nil {
			return "", "", fmt.Errorf("no such directory: %s", parent)
		}
		_ = stat
		return parent, filepath.Base(dst), nil
	default:
		return "", "", fmt.Errorf("reading %s: %w", dst, statErr)
	}
}

// copyToContainer archives a host path and unpacks it inside a container, or
// forwards a tar stream from stdin when the source is "-".
func copyToContainer(ctx context.Context, env *Env, cli *client.Client, srcPath, container, dst string,
	opts client.CopyToContainerOptions, followLink bool) error {

	if srcPath == "-" {
		return cli.CopyToContainer(ctx, container, dst, env.In, opts)
	}
	srcPath = TranslateLocalPath(srcPath)
	info, err := statPath(srcPath, followLink)
	if err != nil {
		return err
	}

	// Work out what the entry should be called inside the container. If the
	// destination exists and is a directory, the source keeps its own name;
	// otherwise the destination's last element renames it.
	destDir := dst
	rename := ""
	if stat, err := cli.ContainerStatPath(ctx, container, dst); err == nil && stat.IsDir() {
		destDir = dst
	} else if err == nil || client.IsNotFound(err) {
		if !info.IsDir() || err == nil {
			destDir = path.Dir(strings.TrimSuffix(dst, "/"))
			rename = path.Base(strings.TrimSuffix(dst, "/"))
		}
	} else {
		return err
	}
	if destDir == "" {
		destDir = "/"
	}

	var buf bytes.Buffer
	if err := tarPath(&buf, srcPath, tarOptions{Rename: rename, FollowLinks: followLink}); err != nil {
		return err
	}
	env.Debugf("copying %s (%d bytes of tar) into %s:%s", srcPath, buf.Len(), container, destDir)
	return cli.CopyToContainer(ctx, container, destDir, &buf, opts)
}

// TranslateLocalPath normalises a host path the CLI itself will open.
//
// Unlike [TranslateHostPath], which rewrites a Windows path into what the
// engine sees inside the VM, this one leaves the path in the local form,
// because "hull cp" reads and writes it with the local os package. It only
// expands "~".
func TranslateLocalPath(p string) string {
	if p == "" || p == "-" {
		return p
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, filepath.FromSlash(p[2:]))
		}
	}
	return p
}
