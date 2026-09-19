package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rahuldhali/hull/internal/client"
)

// newBuildCommand builds "hull build".
func newBuildCommand() *Command {
	var tags, buildArgs, labels []string
	var dockerfile, target, platform, network string
	var noCache, pull, quietFlag, forceRm bool
	var rm = true
	return &Command{
		Name:  "build",
		Usage: "build [OPTIONS] PATH",
		Short: "Build an image from a Dockerfile",
		Long: "Build an image from a Dockerfile.\n\n" +
			"The build context is tarred locally, honouring .dockerignore, and sent\n" +
			"to the engine. A build on an engine with no bundled builder fails with\n" +
			"a 501 whose message names the fix.",
		MinArgs: 1,
		MaxArgs: 1,
		Flags: func(fs *FlagSet) {
			fs.StringSliceVar(&tags, "tag", "t", "Name and optionally a tag (format: name:tag)")
			fs.StringVar(&dockerfile, "file", "f", "", "Name of the Dockerfile (default: PATH/Dockerfile)")
			fs.StringSliceVar(&buildArgs, "build-arg", "", "Set build-time variables")
			fs.StringSliceVar(&labels, "label", "", "Set metadata for an image")
			fs.BoolVar(&noCache, "no-cache", "", false, "Do not use cache when building the image")
			fs.BoolVar(&pull, "pull", "", false, "Always attempt to pull a newer version of the image")
			fs.BoolVar(&quietFlag, "quiet", "q", false, "Suppress the build output and print the image ID on success")
			fs.BoolVar(&forceRm, "force-rm", "", false, "Always remove intermediate containers")
			fs.BoolVar(&rm, "rm", "", true, "Remove intermediate containers after a successful build")
			fs.StringVar(&target, "target", "", "", "Set the target build stage to build")
			fs.StringVar(&platform, "platform", "", "", "Set platform if server is multi-platform capable")
			fs.StringVar(&network, "network", "", "", "Set the networking mode for RUN instructions")
		},
		Run: func(ctx context.Context, env *Env, _ *FlagSet, args []string) error {
			cli, err := env.Client(ctx)
			if err != nil {
				return err
			}
			contextDir := TranslateLocalPath(args[0])
			if contextDir == "-" {
				return Errorf("building from a context on stdin is not supported; pass a directory")
			}
			info, err := os.Stat(contextDir)
			if err != nil {
				return fmt.Errorf("reading build context %s: %w", contextDir, err)
			}
			if !info.IsDir() {
				return Errorf("build context %s is not a directory", contextDir)
			}
			relDockerfile, body, err := buildContext(contextDir, dockerfile)
			if err != nil {
				return err
			}
			opts := client.ImageBuildOptions{
				Tags:        tags,
				Dockerfile:  relDockerfile,
				BuildArgs:   parseBuildArgs(buildArgs),
				Labels:      ParseLabels(labels),
				NoCache:     noCache,
				Pull:        pull,
				Remove:      rm,
				ForceRemove: forceRm,
				Quiet:       quietFlag,
				Target:      target,
				Platform:    platform,
				NetworkMode: network,
			}
			p := NewProgress(env, quietFlag)
			err = cli.ImageBuild(ctx, body, opts, p.Handle)
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

// buildContext tars a directory for the builder and reports the Dockerfile's
// path relative to it.
//
// A Dockerfile outside the context is accepted — "-f ../Dockerfile" is common
// in a monorepo — by adding it to the archive under a generated name, the way
// every builder handles it.
func buildContext(dir, dockerfile string) (string, *bytes.Buffer, error) {
	ignore, err := loadDockerIgnore(dir)
	if err != nil {
		return "", nil, err
	}
	rel := "Dockerfile"
	var extra string
	if dockerfile != "" {
		df := TranslateLocalPath(dockerfile)
		if r, err := filepath.Rel(dir, df); err == nil && !strings.HasPrefix(r, "..") {
			rel = filepath.ToSlash(r)
		} else {
			extra = df
			rel = ".hull-dockerfile"
		}
	}
	var buf bytes.Buffer
	if err := tarPath(&buf, dir, tarOptions{
		Rename: ".",
		Exclude: func(p string) bool {
			// The Dockerfile itself is never excluded, whatever
			// .dockerignore says, because the builder needs it.
			if p == rel {
				return false
			}
			return ignore.Match(p)
		},
	}); err != nil {
		return "", nil, err
	}
	if extra != "" {
		if err := appendFileToTar(&buf, extra, rel); err != nil {
			return "", nil, err
		}
	}
	return rel, &buf, nil
}

// appendFileToTar adds one file to an already-written archive.
//
// A tar stream ends with two zero blocks, so the existing terminator is
// trimmed before the new entry is appended and a fresh one written.
func appendFileToTar(buf *bytes.Buffer, src, name string) error {
	const terminator = 1024
	b := buf.Bytes()
	if len(b) >= terminator && allZero(b[len(b)-terminator:]) {
		buf.Truncate(len(b) - terminator)
	}
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}
	tw := newTarWriter(buf)
	if err := writeTarEntry(tw, src, name, info); err != nil {
		return err
	}
	return tw.Close()
}

// allZero reports whether every byte is zero.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// parseBuildArgs turns "K=V" strings into the builder's map. A bare "K" takes
// its value from the caller's environment, and a "K" that is not set there is
// sent as a null so the builder falls back to the Dockerfile's default.
func parseBuildArgs(entries []string) map[string]*string {
	if len(entries) == 0 {
		return nil
	}
	out := make(map[string]*string, len(entries))
	for _, e := range entries {
		key, value, ok := strings.Cut(e, "=")
		if key == "" {
			continue
		}
		if ok {
			v := value
			out[key] = &v
			continue
		}
		if v, present := os.LookupEnv(key); present {
			val := v
			out[key] = &val
			continue
		}
		out[key] = nil
	}
	return out
}
