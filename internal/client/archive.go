package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// pathStatHeader carries a base64 JSON stat alongside an archive response.
const pathStatHeader = "X-Docker-Container-Path-Stat"

// PathStat describes one path inside a container, as the archive endpoints
// report it.
type PathStat struct {
	// Name is the base name of the path.
	Name string `json:"name"`
	// Size is the file size, or the directory's own size.
	Size int64 `json:"size"`
	// Mode is the file mode bits.
	Mode uint32 `json:"mode"`
	// Mtime is the modification time.
	Mtime time.Time `json:"mtime"`
	// LinkTarget is set when the path is a symlink.
	LinkTarget string `json:"linkTarget,omitempty"`
}

// IsDir reports whether the stat describes a directory.
func (p PathStat) IsDir() bool { return p.Mode&modeDir != 0 }

// modeDir is os.ModeDir's bit, spelled out so this file does not depend on
// the host's os package for a value that arrives over the wire.
const modeDir = 1 << 31

// ContainerStatPath stats one path inside a container without transferring it.
func (c *Client) ContainerStatPath(ctx context.Context, container, path string) (PathStat, error) {
	q := url.Values{"path": []string{path}}
	resp, err := c.do(ctx, http.MethodHead, "/containers/"+url.PathEscape(container)+"/archive", q, nil, nil)
	if err != nil {
		return PathStat{}, err
	}
	defer closeBody(resp)
	return decodePathStat(resp.Header.Get(pathStatHeader))
}

// CopyFromContainer streams one path out of a container as a tar archive, with
// the stat of what is being sent.
func (c *Client) CopyFromContainer(ctx context.Context, container, path string) (io.ReadCloser, PathStat, error) {
	q := url.Values{"path": []string{path}}
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(container)+"/archive", q, nil, nil)
	if err != nil {
		return nil, PathStat{}, err
	}
	stat, err := decodePathStat(resp.Header.Get(pathStatHeader))
	if err != nil {
		_ = resp.Body.Close()
		return nil, PathStat{}, err
	}
	return resp.Body, stat, nil
}

// CopyToContainerOptions configures PUT /containers/{id}/archive.
type CopyToContainerOptions struct {
	// AllowOverwriteDirWithFile permits replacing a directory with a file,
	// which the engine refuses by default.
	AllowOverwriteDirWithFile bool
	// CopyUIDGID preserves the uid and gid recorded in the archive instead of
	// mapping them to the container's user.
	CopyUIDGID bool
}

// CopyToContainer unpacks a tar archive into a directory inside a container.
func (c *Client) CopyToContainer(ctx context.Context, container, path string, content io.Reader, opts CopyToContainerOptions) error {
	q := url.Values{"path": []string{path}}
	if !opts.AllowOverwriteDirWithFile {
		q.Set("noOverwriteDirNonDir", "1")
	}
	boolQuery(q, "copyUIDGID", opts.CopyUIDGID)
	headers := http.Header{}
	headers.Set("Content-Type", "application/x-tar")
	resp, err := c.do(ctx, http.MethodPut, "/containers/"+url.PathEscape(container)+"/archive", q, content, headers)
	if err != nil {
		return err
	}
	closeBody(resp)
	return nil
}

// decodePathStat unwraps the base64 JSON stat header.
func decodePathStat(encoded string) (PathStat, error) {
	if encoded == "" {
		return PathStat{}, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return PathStat{}, fmt.Errorf("client: decode path stat header: %w", err)
	}
	var stat PathStat
	if err := json.Unmarshal(raw, &stat); err != nil {
		return PathStat{}, fmt.Errorf("client: decode path stat: %w", err)
	}
	return stat, nil
}
