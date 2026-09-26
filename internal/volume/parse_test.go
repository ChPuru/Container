package volume

import (
	"errors"
	"strings"
	"testing"

	"github.com/ChPuru/hull/internal/types"
)

func TestTranslateWindowsPath(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr error
		wantMsg string
	}{
		{name: "drive backslash", in: `C:\x`, want: "/mnt/c/x"},
		{name: "drive deep backslash", in: `C:\Users\me\proj`, want: "/mnt/c/Users/me/proj"},
		{name: "drive forward slash lowercase", in: "c:/Users/me/proj", want: "/mnt/c/Users/me/proj"},
		{name: "drive root backslash", in: `C:\`, want: "/mnt/c"},
		{name: "bare drive", in: "C:", want: "/mnt/c"},
		{name: "other drive", in: `E:\a\..\b`, want: "/mnt/e/b"},
		{name: "idempotent wsl mount", in: "/mnt/c/Users/me", want: "/mnt/c/Users/me"},
		{name: "idempotent twice", in: "/mnt/d/proj/", want: "/mnt/d/proj"},
		{name: "plain linux path", in: "/home/you/proj", want: "/home/you/proj"},
		{name: "git-bash double slash", in: "//var/run/docker.sock", want: "/var/run/docker.sock"},

		{name: "wsl unc backslash", in: `\\wsl$\Ubuntu\home\me`, wantErr: ErrUNCPath, wantMsg: uncAdvice},
		{name: "wsl unc forward", in: "//wsl$/Ubuntu/home/me", wantErr: ErrUNCPath, wantMsg: uncAdvice},
		{name: "wsl localhost unc", in: `\\wsl.localhost\Ubuntu\home\me`, wantErr: ErrUNCPath, wantMsg: uncAdvice},
		{name: "other unc", in: `\\server\share\dir`, wantErr: ErrUNCPath, wantMsg: "UNC path"},
		{name: "relative", in: "proj", wantErr: ErrInvalidMount, wantMsg: "not absolute"},
		{name: "dot relative", in: "./proj", wantErr: ErrInvalidMount, wantMsg: "not absolute"},
		{name: "empty", in: "", wantErr: ErrInvalidMount},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TranslateWindowsPath(tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("TranslateWindowsPath(%q) error = %v, want %v", tc.in, err, tc.wantErr)
				}
				if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("TranslateWindowsPath(%q) error %q does not mention %q", tc.in, err, tc.wantMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("TranslateWindowsPath(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("TranslateWindowsPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestTranslateWindowsPathIsIdempotent(t *testing.T) {
	for _, in := range []string{`C:\Users\me\proj`, "c:/Users/me/proj", "/home/you/proj", "//var/run/x"} {
		once, err := TranslateWindowsPath(in)
		if err != nil {
			t.Fatalf("TranslateWindowsPath(%q): %v", in, err)
		}
		twice, err := TranslateWindowsPath(once)
		if err != nil {
			t.Fatalf("TranslateWindowsPath(%q): %v", once, err)
		}
		if once != twice {
			t.Fatalf("TranslateWindowsPath not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}

func TestParseBind(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    types.Mount
		wantErr error
		wantMsg string
	}{
		{
			name: "anonymous volume",
			in:   "/ctr",
			want: types.Mount{Type: TypeVolume, Target: "/ctr"},
		},
		{
			name: "host bind",
			in:   "/host:/ctr",
			want: types.Mount{Type: TypeBind, Source: "/host", Target: "/ctr"},
		},
		{
			name: "host bind readonly",
			in:   "/host:/ctr:ro",
			want: types.Mount{Type: TypeBind, Source: "/host", Target: "/ctr", ReadOnly: true},
		},
		{
			name: "named volume with rw and selinux label",
			in:   "name:/ctr:rw,z",
			want: types.Mount{Type: TypeVolume, Source: "name", Target: "/ctr"},
		},
		{
			name: "named volume nocopy",
			in:   "db:/var/lib/db:nocopy",
			want: types.Mount{Type: TypeVolume, Source: "db", Target: "/var/lib/db", Consistency: ConsistencyNoCopy},
		},
		{
			name: "windows backslash source",
			in:   `C:\Users\me\proj:/app`,
			want: types.Mount{Type: TypeBind, Source: "/mnt/c/Users/me/proj", Target: "/app"},
		},
		{
			name: "windows forward slash source readonly",
			in:   "c:/Users/me/proj:/app:ro",
			want: types.Mount{Type: TypeBind, Source: "/mnt/c/Users/me/proj", Target: "/app", ReadOnly: true},
		},
		{
			name: "windows drive root",
			in:   `D:\:/data:rw`,
			want: types.Mount{Type: TypeBind, Source: "/mnt/d", Target: "/data"},
		},
		{
			name: "windows uppercase drive deep target",
			in:   `E:\code\hull:/src/hull:ro`,
			want: types.Mount{Type: TypeBind, Source: "/mnt/e/code/hull", Target: "/src/hull", ReadOnly: true},
		},
		{
			name: "git bash double slash source",
			in:   "//var/run/docker.sock:/var/run/docker.sock",
			want: types.Mount{Type: TypeBind, Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"},
		},
		{
			name: "bind propagation",
			in:   "/host:/ctr:ro,rslave",
			want: types.Mount{Type: TypeBind, Source: "/host", Target: "/ctr", ReadOnly: true, BindOptions: &types.BindOptions{Propagation: "rslave"}},
		},
		{
			name: "target is cleaned",
			in:   "/host:/ctr/./sub/",
			want: types.Mount{Type: TypeBind, Source: "/host", Target: "/ctr/sub"},
		},

		{name: "wsl unc source", in: `\\wsl$\Ubuntu\home\me\proj:/app`, wantErr: ErrUNCPath, wantMsg: uncAdvice},
		{name: "wsl localhost unc source", in: `\\wsl.localhost\Ubuntu\home\me:/app`, wantErr: ErrUNCPath, wantMsg: uncAdvice},
		{name: "wsl unc forward slash source", in: "//wsl$/Ubuntu/home/me:/app", wantErr: ErrUNCPath, wantMsg: uncAdvice},
		{name: "other unc source", in: `\\server\share:/app`, wantErr: ErrUNCPath},
		{name: "empty", in: "", wantErr: ErrInvalidMount},
		{name: "root target", in: "/host:/", wantErr: ErrInvalidMount, wantMsg: "container root"},
		{name: "root target dotted", in: "/host:/.", wantErr: ErrInvalidMount, wantMsg: "container root"},
		{name: "relative target", in: "/host:ctr", wantErr: ErrInvalidMount, wantMsg: "absolute"},
		{name: "relative source", in: "./proj:/app", wantErr: ErrInvalidMount, wantMsg: "not absolute"},
		{name: "windows relative source", in: `sub\proj:/app`, wantErr: ErrInvalidMount, wantMsg: "not absolute"},
		{name: "too many fields", in: "/a:/b:/c:/d", wantErr: ErrInvalidMount, wantMsg: "at most 3"},
		{name: "unknown option", in: "/host:/ctr:bogus", wantErr: ErrInvalidMount, wantMsg: "unknown option"},
		{name: "propagation on volume", in: "db:/ctr:rslave", wantErr: ErrInvalidMount, wantMsg: "bind mount"},
		{name: "nocopy on bind", in: "/host:/ctr:nocopy", wantErr: ErrInvalidMount, wantMsg: "volume mount"},
		{name: "windows target", in: `/host:C:\app`, wantErr: ErrInvalidMount},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseBind(tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseBind(%q) error = %v, want %v", tc.in, err, tc.wantErr)
				}
				if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("ParseBind(%q) error %q does not mention %q", tc.in, err, tc.wantMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBind(%q) unexpected error: %v", tc.in, err)
			}
			assertMountEqual(t, tc.in, got, tc.want)
		})
	}
}

func TestParseMount(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    types.Mount
		wantErr error
		wantMsg string
	}{
		{
			name: "bind readonly bare flag",
			in:   "type=bind,source=/host,target=/ctr,readonly",
			want: types.Mount{Type: TypeBind, Source: "/host", Target: "/ctr", ReadOnly: true},
		},
		{
			name: "bind readonly false",
			in:   "type=bind,source=/host,target=/ctr,readonly=false",
			want: types.Mount{Type: TypeBind, Source: "/host", Target: "/ctr"},
		},
		{
			name: "volume short keys",
			in:   "type=volume,src=db,dst=/var/lib/postgresql/data",
			want: types.Mount{Type: TypeVolume, Source: "db", Target: "/var/lib/postgresql/data"},
		},
		{
			name: "type defaults to volume",
			in:   "src=db,dst=/data",
			want: types.Mount{Type: TypeVolume, Source: "db", Target: "/data"},
		},
		{
			name: "anonymous volume",
			in:   "type=volume,target=/data",
			want: types.Mount{Type: TypeVolume, Target: "/data"},
		},
		{
			name: "volume nocopy",
			in:   "type=volume,src=db,dst=/data,volume-nocopy",
			want: types.Mount{Type: TypeVolume, Source: "db", Target: "/data", Consistency: ConsistencyNoCopy},
		},
		{
			name: "tmpfs with size and mode",
			in:   "type=tmpfs,target=/run,tmpfs-size=64m,tmpfs-mode=1777",
			want: types.Mount{Type: TypeTmpfs, Target: "/run", TmpfsOptions: &types.TmpfsOptions{SizeBytes: 64 << 20, Mode: 0o1777}},
		},
		{
			name: "windows source",
			in:   `type=bind,source=C:\Users\me\proj,target=/app,bind-propagation=rslave`,
			want: types.Mount{Type: TypeBind, Source: "/mnt/c/Users/me/proj", Target: "/app", BindOptions: &types.BindOptions{Propagation: "rslave"}},
		},
		{
			name: "quoted value containing a comma",
			in:   `type=bind,"source=/host/a,b",target=/ctr`,
			want: types.Mount{Type: TypeBind, Source: "/host/a,b", Target: "/ctr"},
		},
		{
			name: "quoted windows value containing a comma",
			in:   `type=bind,"source=C:\Users\me\a,b",target=/app,readonly`,
			want: types.Mount{Type: TypeBind, Source: "/mnt/c/Users/me/a,b", Target: "/app", ReadOnly: true},
		},
		{
			name: "spaces around fields",
			in:   "type=bind, source=/host, target=/ctr",
			want: types.Mount{Type: TypeBind, Source: "/host", Target: "/ctr"},
		},
		{
			name: "consistency accepted and dropped",
			in:   "type=bind,source=/host,target=/ctr,consistency=cached",
			want: types.Mount{Type: TypeBind, Source: "/host", Target: "/ctr"},
		},

		{name: "no target", in: "type=bind,source=/host", wantErr: ErrInvalidMount, wantMsg: "requires target="},
		{name: "bind without source", in: "type=bind,target=/ctr", wantErr: ErrInvalidMount, wantMsg: "requires source="},
		{name: "tmpfs with source", in: "type=tmpfs,source=/x,target=/run", wantErr: ErrInvalidMount, wantMsg: "must not have a source"},
		{name: "unknown type", in: "type=nfs,target=/x", wantErr: ErrInvalidMount, wantMsg: "unknown mount type"},
		{name: "unknown field", in: "type=bind,source=/host,target=/ctr,wat=1", wantErr: ErrInvalidMount, wantMsg: "unknown --mount field"},
		{name: "bad propagation", in: "type=bind,source=/host,target=/ctr,bind-propagation=sideways", wantErr: ErrInvalidMount, wantMsg: "invalid bind-propagation"},
		{name: "bad tmpfs size", in: "type=tmpfs,target=/run,tmpfs-size=lots", wantErr: ErrInvalidMount},
		{name: "bad tmpfs mode", in: "type=tmpfs,target=/run,tmpfs-mode=99", wantErr: ErrInvalidMount, wantMsg: "octal"},
		{name: "tmpfs option on bind", in: "type=bind,source=/host,target=/ctr,tmpfs-size=1m", wantErr: ErrInvalidMount, wantMsg: "only valid on a tmpfs mount"},
		{name: "unsupported volume driver", in: "type=volume,dst=/d,volume-driver=nfs", wantErr: ErrDriverUnsupported},
		{name: "volume opt cannot round-trip", in: `type=volume,dst=/d,"volume-opt=o=size=64m,uid=1000"`, wantErr: ErrInvalidMount, wantMsg: "volume-opt"},
		{name: "unc source", in: `type=bind,source=\\wsl$\Ubuntu\home,target=/app`, wantErr: ErrUNCPath, wantMsg: uncAdvice},
		{name: "empty", in: "", wantErr: ErrInvalidMount},
		{name: "root target", in: "type=bind,source=/host,target=/", wantErr: ErrInvalidMount, wantMsg: "container root"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMount(tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseMount(%q) error = %v, want %v", tc.in, err, tc.wantErr)
				}
				if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("ParseMount(%q) error %q does not mention %q", tc.in, err, tc.wantMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMount(%q) unexpected error: %v", tc.in, err)
			}
			assertMountEqual(t, tc.in, got, tc.want)
		})
	}
}

func TestParseMountSpecKeepsVolumeOptions(t *testing.T) {
	// The whole field is quoted, which is how docker documents a volume-opt
	// whose value contains a comma.
	const in = `type=volume,dst=/c,volume-driver=local,volume-opt=type=tmpfs,"volume-opt=o=size=64m,uid=1000",volume-label=team=infra,volume-nocopy`
	sp, err := ParseMountSpec(in)
	if err != nil {
		t.Fatalf("ParseMountSpec: %v", err)
	}
	if sp.VolumeDriver != DriverLocal {
		t.Fatalf("VolumeDriver = %q, want %q", sp.VolumeDriver, DriverLocal)
	}
	if got := sp.VolumeOptions["o"]; got != "size=64m,uid=1000" {
		t.Fatalf("volume-opt o = %q, want %q", got, "size=64m,uid=1000")
	}
	if got := sp.VolumeOptions["type"]; got != "tmpfs" {
		t.Fatalf("volume-opt type = %q, want tmpfs", got)
	}
	if got := sp.VolumeLabels["team"]; got != "infra" {
		t.Fatalf("volume-label team = %q, want infra", got)
	}
	if !sp.NoCopy || sp.Mount.Consistency != ConsistencyNoCopy {
		t.Fatalf("nocopy not carried: NoCopy=%v Consistency=%q", sp.NoCopy, sp.Mount.Consistency)
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{in: "1024", want: 1024},
		{in: "64m", want: 64 << 20},
		{in: "64M", want: 64 << 20},
		{in: "1g", want: 1 << 30},
		{in: "1kb", want: 1024},
		{in: "1kib", want: 1024},
		{in: "1.5k", want: 1536},
		{in: "512b", want: 512},
		{in: "0", want: 0},
		{in: "", wantErr: true},
		{in: "lots", wantErr: true},
		{in: "-1m", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseSize(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSize(%q) = %d, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSize(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidateName(t *testing.T) {
	good := []string{"db", "my-vol", "my_vol.1", "A1", strings.Repeat("a", maxNameLen)}
	for _, n := range good {
		if err := ValidateName(n); err != nil {
			t.Fatalf("ValidateName(%q) = %v, want nil", n, err)
		}
	}
	bad := []string{"", "a", "-leading", "has/slash", `has\backslash`, "..", "refs.json", strings.Repeat("a", maxNameLen+1)}
	for _, n := range bad {
		if err := ValidateName(n); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("ValidateName(%q) = %v, want ErrInvalidName", n, err)
		}
	}
}

// assertMountEqual compares two mounts field by field so a failure names the
// field that differs rather than dumping two structs.
func assertMountEqual(t *testing.T, in string, got, want types.Mount) {
	t.Helper()
	if got.Type != want.Type {
		t.Errorf("%q: Type = %q, want %q", in, got.Type, want.Type)
	}
	if got.Source != want.Source {
		t.Errorf("%q: Source = %q, want %q", in, got.Source, want.Source)
	}
	if got.Target != want.Target {
		t.Errorf("%q: Target = %q, want %q", in, got.Target, want.Target)
	}
	if got.ReadOnly != want.ReadOnly {
		t.Errorf("%q: ReadOnly = %v, want %v", in, got.ReadOnly, want.ReadOnly)
	}
	if got.Consistency != want.Consistency {
		t.Errorf("%q: Consistency = %q, want %q", in, got.Consistency, want.Consistency)
	}
	switch {
	case want.BindOptions == nil && got.BindOptions != nil:
		t.Errorf("%q: BindOptions = %+v, want nil", in, got.BindOptions)
	case want.BindOptions != nil && got.BindOptions == nil:
		t.Errorf("%q: BindOptions = nil, want %+v", in, want.BindOptions)
	case want.BindOptions != nil && *got.BindOptions != *want.BindOptions:
		t.Errorf("%q: BindOptions = %+v, want %+v", in, *got.BindOptions, *want.BindOptions)
	}
	switch {
	case want.TmpfsOptions == nil && got.TmpfsOptions != nil:
		t.Errorf("%q: TmpfsOptions = %+v, want nil", in, got.TmpfsOptions)
	case want.TmpfsOptions != nil && got.TmpfsOptions == nil:
		t.Errorf("%q: TmpfsOptions = nil, want %+v", in, want.TmpfsOptions)
	case want.TmpfsOptions != nil && *got.TmpfsOptions != *want.TmpfsOptions:
		t.Errorf("%q: TmpfsOptions = %+v, want %+v", in, *got.TmpfsOptions, *want.TmpfsOptions)
	}
}
