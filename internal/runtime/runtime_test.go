package runtime

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

func TestValidID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		ok   bool
	}{
		{name: "hex id", id: "0123456789abcdef", ok: true},
		{name: "name with dashes", id: "my-container-1", ok: true},
		{name: "name with dots", id: "web.1", ok: true},
		{name: "underscore", id: "web_1", ok: true},
		{name: "empty"},
		{name: "dot"},
		{name: "dot dot", id: ".."},
		{name: "slash escapes the state dir", id: "../../etc/passwd"},
		{name: "embedded slash", id: "a/b"},
		{name: "null byte", id: "a\x00b"},
		{name: "newline", id: "a\nb"},
		{name: "space", id: "a b"},
		{name: "too long", id: strings.Repeat("a", 129)},
		{name: "at the limit", id: strings.Repeat("a", 128), ok: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidID(tc.id)
			if tc.ok && err != nil {
				t.Fatalf("ValidID(%q) = %v, want nil", tc.id, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("ValidID(%q) accepted an unsafe id", tc.id)
			}
		})
	}
}

func writeBundle(t *testing.T, spec *runtimespec.Spec) string {
	t.Helper()
	dir := t.TempDir()
	if spec.Root != nil && spec.Root.Path != "" && !filepath.IsAbs(spec.Root.Path) {
		if err := os.MkdirAll(filepath.Join(dir, spec.Root.Path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	b, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigFileName), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func minimalSpec() *runtimespec.Spec {
	s := runtimespec.DefaultSpec()
	s.Root = &runtimespec.Root{Path: "rootfs"}
	s.Process.Args = []string{"/bin/true"}
	s.Process.Cwd = "/"
	return s
}

func TestLoadSpec(t *testing.T) {
	dir := writeBundle(t, minimalSpec())
	spec, err := LoadSpec(dir)
	if err != nil {
		t.Fatalf("LoadSpec: %v", err)
	}
	if spec.Version != runtimespec.Version {
		t.Errorf("version = %q, want %q", spec.Version, runtimespec.Version)
	}
	if spec.Root.Path != "rootfs" {
		t.Errorf("root = %q", spec.Root.Path)
	}

	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadSpec(t.TempDir()); err == nil {
			t.Fatal("LoadSpec accepted a directory with no config.json")
		}
	})
	t.Run("malformed json", func(t *testing.T) {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, ConfigFileName), []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSpec(d); err == nil {
			t.Fatal("LoadSpec accepted malformed json")
		}
	})
	t.Run("unknown fields are tolerated", func(t *testing.T) {
		d := t.TempDir()
		raw := `{"ociVersion":"1.2.0","hullFutureField":42,` +
			`"root":{"path":"rootfs"},"process":{"args":["/bin/true"],"cwd":"/","user":{"uid":0,"gid":0}},` +
			`"linux":{}}`
		if err := os.WriteFile(filepath.Join(d, ConfigFileName), []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSpec(d); err != nil {
			t.Fatalf("LoadSpec rejected an unknown field: %v", err)
		}
	})
	t.Run("invalid spec is rejected", func(t *testing.T) {
		s := minimalSpec()
		s.Process.Cwd = "relative"
		d := writeBundle(t, s)
		if _, err := LoadSpec(d); err == nil {
			t.Fatal("LoadSpec accepted a spec with a relative cwd")
		}
	})
}

func TestStatusRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := &Status{
		ID: "abc", Pid: 4242, Status: StatusRunning, Bundle: "/bundle",
		Created: time.Now().UTC().Truncate(time.Second), ExitCode: 0,
	}
	if err := saveStatus(dir, in); err != nil {
		t.Fatalf("saveStatus: %v", err)
	}
	out, err := loadStatus(dir)
	if err != nil {
		t.Fatalf("loadStatus: %v", err)
	}
	if out.ID != in.ID || out.Pid != in.Pid || out.Status != in.Status || !out.Created.Equal(in.Created) {
		t.Fatalf("round trip lost data: %+v vs %+v", out, in)
	}
	if _, err := loadStatus(t.TempDir()); !os.IsNotExist(err) {
		t.Fatalf("loadStatus on an empty dir = %v, want IsNotExist", err)
	}
	// The temp file must not be left behind.
	if _, err := os.Stat(filepath.Join(dir, ".state.json.tmp")); err == nil {
		t.Error("saveStatus left its temporary file behind")
	}
}

func TestResourcesFromSpec(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	u64 := func(v uint64) *uint64 { return &v }
	u16 := func(v uint16) *uint16 { return &v }

	tests := []struct {
		name  string
		in    *runtimespec.LinuxResources
		check func(*testing.T, any)
	}{
		{name: "nil", in: nil},
		{
			name: "memory and cpu",
			in: &runtimespec.LinuxResources{
				Memory: &runtimespec.LinuxMemory{Limit: i64(512 << 20), Reservation: i64(256 << 20), Swap: i64(1 << 30)},
				CPU:    &runtimespec.LinuxCPU{Shares: u64(512), Quota: i64(50000), Period: u64(100000), Cpus: "0-3"},
			},
		},
		{name: "blkio", in: &runtimespec.LinuxResources{BlockIO: &runtimespec.LinuxBlockIO{Weight: u16(300)}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resourcesFromSpec(tc.in)
			if tc.in == nil {
				if got.Memory != 0 || got.CPUShares != 0 {
					t.Fatalf("nil resources produced %+v", got)
				}
				return
			}
			if m := tc.in.Memory; m != nil {
				if got.Memory != *m.Limit || got.MemoryReservation != *m.Reservation || got.MemorySwap != *m.Swap {
					t.Errorf("memory mapped wrong: %+v", got)
				}
			}
			if c := tc.in.CPU; c != nil {
				if got.CPUShares != int64(*c.Shares) || got.CPUQuota != *c.Quota ||
					got.CPUPeriod != int64(*c.Period) || got.CpusetCpus != c.Cpus {
					t.Errorf("cpu mapped wrong: %+v", got)
				}
			}
			if b := tc.in.BlockIO; b != nil && got.BlkioWeight != *b.Weight {
				t.Errorf("blkio weight = %d, want %d", got.BlkioWeight, *b.Weight)
			}
		})
	}
	// The exported form must agree with the internal one.
	res := &runtimespec.LinuxResources{Memory: &runtimespec.LinuxMemory{Limit: i64(1)}}
	if SpecResources(res) != resourcesFromSpec(res) {
		t.Error("SpecResources disagrees with resourcesFromSpec")
	}
}

func TestMapCrunError(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{name: "not found", in: `container "abc" does not exist`, want: ErrNotFound},
		{name: "not running", in: `container abc is not running`, want: ErrNotRunning},
		{name: "already exists", in: `container abc already exists`, want: ErrExists},
		{
			name: "crun's missing status file",
			in:   "error opening file `/var/lib/hull/runtime/abc/status`: No such file or directory",
			want: ErrNotFound,
		},
		{name: "something else", in: `permission denied`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapCrunError(errors.New(tc.in), "abc")
			if tc.want == nil {
				if errors.Is(got, ErrNotFound) || errors.Is(got, ErrNotRunning) || errors.Is(got, ErrExists) {
					t.Fatalf("mapCrunError invented a sentinel for %q: %v", tc.in, got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("mapCrunError(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
	if mapCrunError(nil, "abc") != nil {
		t.Fatal("mapCrunError(nil) must stay nil")
	}
}

func TestBundleFor(t *testing.T) {
	if bundleFor(nil, nil, nil, nil) != nil {
		t.Fatal("bundleFor with nothing should return nil so stdout stays captured")
	}
	var sb strings.Builder
	b := bundleFor(nil, &sb, nil, nil)
	if b == nil || b.out == nil || b.in != nil {
		t.Fatalf("bundleFor did not carry the writer: %+v", b)
	}
}

func TestCrunStateParsing(t *testing.T) {
	raw := `{"ociVersion":"1.0.2","id":"abc","status":"running","pid":1234,` +
		`"bundle":"/var/lib/hull/containers/abc","annotations":{"hull.test":"1"}}`
	var cs crunState
	if err := json.Unmarshal([]byte(raw), &cs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cs.ID != "abc" || cs.Pid != 1234 || cs.Status != "running" {
		t.Fatalf("parsed %+v", cs)
	}
	if cs.Annotations["hull.test"] != "1" {
		t.Errorf("annotations lost: %v", cs.Annotations)
	}
}

func TestNewCrunRejectsEmptyRoot(t *testing.T) {
	if _, err := NewCrun("", ""); err == nil {
		t.Fatal("NewCrun accepted an empty state root")
	}
}

func TestNewCrunUnknownBinary(t *testing.T) {
	_, err := NewCrun("hull-definitely-not-a-runtime", t.TempDir())
	if err == nil {
		t.Fatal("NewCrun found a runtime that does not exist")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want it to wrap ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "Install crun") {
		t.Errorf("the error should tell the operator what to do: %v", err)
	}
}

func TestRuntimeInterfaceIsSatisfied(t *testing.T) {
	// Compile-time assertions live in the driver files; this makes the
	// intent visible in the test output too.
	var _ Runtime = (*CrunRuntime)(nil)
	var _ Runtime = (*NativeRuntime)(nil)
}
