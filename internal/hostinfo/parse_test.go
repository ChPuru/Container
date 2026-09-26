package hostinfo

import (
	"bytes"
	"compress/gzip"
	"reflect"
	"strings"
	"testing"
)

// goldenMounts is a verbatim excerpt of /proc/mounts from the WSL 2.4.13
// kernel 5.15.167.4 host hull targets: hybrid cgroups, a 9p Windows share and
// the shared /mnt/wsl tmpfs.
const goldenMounts = `/dev/sdc / ext4 rw,relatime,discard,errors=remount-ro,data=ordered 0 0
none /mnt/wsl tmpfs rw,relatime 0 0
tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,size=4096k,nr_inodes=1024,mode=755 0 0
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/pids cgroup rw,nosuid,nodev,noexec,relatime,pids 0 0
cgroup /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0
drivers /usr/lib/wsl/drivers 9p ro,dirsync,noatime,aname=drivers;fmask=222,mmap,access=client,msize=65536,trans=fd,rfd=8,wfd=8 0 0
C:\134 /mnt/c 9p rw,dirsync,noatime,aname=drvfs;path=C:\134;uid=0;gid=0;metadata;symlinkroot=/mnt/ 0 0
none /var/lib/hull\040data ext4 rw,relatime 0 0
`

func TestParseMounts(t *testing.T) {
	got, err := ParseMounts(strings.NewReader(goldenMounts))
	if err != nil {
		t.Fatalf("ParseMounts: %v", err)
	}
	if len(got) != 11 {
		t.Fatalf("got %d entries, want 11", len(got))
	}

	tests := []struct {
		name    string
		target  string
		wantFS  string
		wantSrc string
		wantOpt string
		noOpt   string
	}{
		{"root", "/", "ext4", "/dev/sdc", "rw", "nsdelegate"},
		{"shared wsl tmpfs", "/mnt/wsl", "tmpfs", "none", "relatime", "ro"},
		{"cgroup2 unified", "/sys/fs/cgroup/unified", "cgroup2", "cgroup2", "nsdelegate", "cpuset"},
		{"cgroup v1 memory", "/sys/fs/cgroup/memory", "cgroup", "cgroup", "memory", "nsdelegate"},
		{"windows drive share", "/mnt/c", "9p", `C:\`, "aname", "nsdelegate"},
		{"escaped space in target", "/var/lib/hull data", "ext4", "none", "rw", "ro"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ok := FindMount(got, tt.target)
			if !ok {
				t.Fatalf("no mount at %q", tt.target)
			}
			if m.FSType != tt.wantFS {
				t.Errorf("fstype = %q, want %q", m.FSType, tt.wantFS)
			}
			if m.Source != tt.wantSrc {
				t.Errorf("source = %q, want %q", m.Source, tt.wantSrc)
			}
			if !m.HasOption(tt.wantOpt) {
				t.Errorf("missing option %q in %v", tt.wantOpt, m.Options)
			}
			if m.HasOption(tt.noOpt) {
				t.Errorf("unexpected option %q in %v", tt.noOpt, m.Options)
			}
		})
	}
}

func TestFindMountFor(t *testing.T) {
	mounts, err := ParseMounts(strings.NewReader(goldenMounts))
	if err != nil {
		t.Fatalf("ParseMounts: %v", err)
	}
	tests := []struct {
		name   string
		path   string
		want   string
		wantFS string
	}{
		{"exact mountpoint", "/mnt/c", "/mnt/c", "9p"},
		{"below a mountpoint", "/mnt/c/Users/Lenovo", "/mnt/c", "9p"},
		{"falls back to root", "/var/lib/hull", "/", "ext4"},
		{"root itself", "/", "/", "ext4"},
		{"longest prefix wins", "/sys/fs/cgroup/unified/hull", "/sys/fs/cgroup/unified", "cgroup2"},
		{"no false prefix match", "/mnt/cdrom", "/", "ext4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ok := FindMountFor(mounts, tt.path)
			if !ok {
				t.Fatalf("no governing mount for %q", tt.path)
			}
			if m.Target != tt.want || m.FSType != tt.wantFS {
				t.Errorf("got %q (%s), want %q (%s)", m.Target, m.FSType, tt.want, tt.wantFS)
			}
		})
	}
}

func TestParseKernelRelease(t *testing.T) {
	tests := []struct {
		name              string
		in                string
		wantMaj, wantMin  int
		wantErr           bool
		atLeast515        bool
		atLeast66         bool
		atLeastFiveTenArg bool
	}{
		{name: "wsl 5.15", in: "5.15.167.4-microsoft-standard-WSL2", wantMaj: 5, wantMin: 15, atLeast515: true, atLeastFiveTenArg: true},
		{name: "wsl 6.6", in: "6.6.87.2-microsoft-standard-WSL2", wantMaj: 6, wantMin: 6, atLeast515: true, atLeast66: true, atLeastFiveTenArg: true},
		{name: "wsl 6.18 preview", in: "6.18.0-microsoft-standard-WSL2+", wantMaj: 6, wantMin: 18, atLeast515: true, atLeast66: true, atLeastFiveTenArg: true},
		{name: "plain three-part", in: "5.10.0", wantMaj: 5, wantMin: 10, atLeastFiveTenArg: true},
		{name: "major only", in: "6", wantMaj: 6, wantMin: 0, atLeast515: true, atLeast66: false, atLeastFiveTenArg: true},
		{name: "rc suffix", in: "6.7.0-rc3", wantMaj: 6, wantMin: 7, atLeast515: true, atLeast66: true, atLeastFiveTenArg: true},
		{name: "trailing whitespace", in: " 5.4.72-generic\n", wantMaj: 5, wantMin: 4},
		{name: "double digit minor", in: "4.19.128", wantMaj: 4, wantMin: 19},
		{name: "empty", in: "", wantErr: true},
		{name: "non numeric", in: "microsoft-standard", wantErr: true},
		{name: "trailing dot", in: "5.", wantErr: true},
		{name: "non numeric minor", in: "5.x.1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maj, min, err := ParseKernelRelease(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %d.%d", maj, min)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseKernelRelease(%q): %v", tt.in, err)
			}
			if maj != tt.wantMaj || min != tt.wantMin {
				t.Fatalf("got %d.%d, want %d.%d", maj, min, tt.wantMaj, tt.wantMin)
			}
			k := KernelInfo{Major: maj, Minor: min}
			if got := k.AtLeast(5, 15); got != tt.atLeast515 {
				t.Errorf("AtLeast(5,15) = %v, want %v", got, tt.atLeast515)
			}
			if got := k.AtLeast(6, 6); got != tt.atLeast66 {
				t.Errorf("AtLeast(6,6) = %v, want %v", got, tt.atLeast66)
			}
			if got := k.AtLeast(5, 10); got != tt.atLeastFiveTenArg {
				t.Errorf("AtLeast(5,10) = %v, want %v", got, tt.atLeastFiveTenArg)
			}
		})
	}
}

const goldenConfig = `#
# Automatically generated file; DO NOT EDIT.
# Linux/x86 5.15.167.4 Kernel Configuration
#
CONFIG_CGROUPS=y
CONFIG_USER_NS=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
# CONFIG_PSI is not set
CONFIG_OVERLAY_FS=y
CONFIG_BRIDGE=y
CONFIG_VETH=y
CONFIG_NF_TABLES=m
CONFIG_SECURITY_LANDLOCK=y
CONFIG_LOCALVERSION="-microsoft-standard-WSL2"
CONFIG_DEFAULT_HOSTNAME="(none)"

CONFIG_HZ=250
`

func TestParseKernelConfigGz(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(goldenConfig)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	cfg, err := ParseKernelConfig(&buf)
	if err != nil {
		t.Fatalf("ParseKernelConfig: %v", err)
	}

	tests := []struct {
		key     string
		want    string
		present bool
	}{
		{"CONFIG_CGROUPS", "y", true},
		{"CONFIG_NF_TABLES", "m", true},
		{"CONFIG_PSI", "", false},
		{"CONFIG_LOCALVERSION", "-microsoft-standard-WSL2", true},
		{"CONFIG_HZ", "250", true},
		{"CONFIG_NOT_THERE", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got, ok := cfg[tt.key]
			if ok != tt.present {
				t.Fatalf("present = %v, want %v (value %q)", ok, tt.present, got)
			}
			if got != tt.want {
				t.Errorf("value = %q, want %q", got, tt.want)
			}
		})
	}

	if !configIs(cfg, "CONFIG_NF_TABLES", "y", "m") {
		t.Error("configIs should accept a module-valued option")
	}
	if configIs(cfg, "CONFIG_PSI", "y") {
		t.Error("configIs must not report an unset option as enabled")
	}
}

func TestParseKernelConfigGzBadStream(t *testing.T) {
	if _, err := ParseKernelConfig(strings.NewReader("not gzip at all")); err == nil {
		t.Fatal("want an error for a non-gzip stream")
	}
}

func TestParseOSRelease(t *testing.T) {
	const golden = `PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
# a comment

HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
SINGLE='quoted'
`
	got, err := ParseOSRelease(strings.NewReader(golden))
	if err != nil {
		t.Fatalf("ParseOSRelease: %v", err)
	}
	tests := []struct{ key, want string }{
		{"ID", "ubuntu"},
		{"NAME", "Ubuntu"},
		{"PRETTY_NAME", "Ubuntu 24.04.3 LTS"},
		{"VERSION_ID", "24.04"},
		{"UBUNTU_CODENAME", "noble"},
		{"SINGLE", "quoted"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got[tt.key] != tt.want {
				t.Errorf("%s = %q, want %q", tt.key, got[tt.key], tt.want)
			}
		})
	}
	if len(got) != 8 {
		t.Errorf("got %d keys, want 8: %v", len(got), got)
	}
}

func TestParseModules(t *testing.T) {
	const golden = `overlay 151552 0 - Live 0xffffffffc0350000
br_netfilter 32768 0 - Live 0xffffffffc0340000
bridge 311296 1 br_netfilter, Live 0xffffffffc02f0000
veth 32768 0 - Live 0xffffffffc02e0000
`
	tests := []struct {
		name string
		in   string
		want map[string]bool
	}{
		{
			name: "loaded modules",
			in:   golden,
			want: map[string]bool{"overlay": true, "br_netfilter": true, "bridge": true, "veth": true},
		},
		{
			name: "empty file means everything is built in",
			in:   "",
			want: map[string]bool{},
		},
		{
			name: "blank lines are ignored",
			in:   "\n\nveth 32768 0 - Live 0x0\n\n",
			want: map[string]bool{"veth": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseModules(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("ParseModules: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// goldenStatus is a verbatim /proc/self/status excerpt from the target host.
const goldenStatus = `Name:	cat
Umask:	0022
State:	R (running)
Tgid:	4242
Pid:	4242
PPid:	4100
Uid:	0	0	0	0
Gid:	0	0	0	0
CapInh:	0000000000000000
CapPrm:	000001ffffffffff
CapEff:	000001ffffffffff
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
`

func TestParseProcStatusField(t *testing.T) {
	tests := []struct {
		key      string
		want     string
		wantSeen bool
	}{
		{"CapBnd", "000001ffffffffff", true},
		{"CapAmb", "0000000000000000", true},
		{"NoNewPrivs", "0", true},
		{"Name", "cat", true},
		{"NotAField", "", false},
		// Must not match a prefix of a longer key.
		{"Cap", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got, ok, err := ParseProcStatusField(strings.NewReader(goldenStatus), tt.key)
			if err != nil {
				t.Fatalf("ParseProcStatusField: %v", err)
			}
			if ok != tt.wantSeen || got != tt.want {
				t.Errorf("got (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantSeen)
			}
		})
	}
}

func TestParseCapBnd(t *testing.T) {
	caps, err := ParseCapBnd(strings.NewReader(goldenStatus))
	if err != nil {
		t.Fatalf("ParseCapBnd: %v", err)
	}
	// 0x1ffffffffff is bits 0..40 set: the full modern bounding set.
	if len(caps) != 41 {
		t.Fatalf("got %d capabilities, want 41: %v", len(caps), caps)
	}
	if caps[0] != "CAP_CHOWN" {
		t.Errorf("caps[0] = %q, want CAP_CHOWN", caps[0])
	}
	if caps[21] != "CAP_SYS_ADMIN" {
		t.Errorf("caps[21] = %q, want CAP_SYS_ADMIN", caps[21])
	}
	if caps[40] != "CAP_CHECKPOINT_RESTORE" {
		t.Errorf("caps[40] = %q, want CAP_CHECKPOINT_RESTORE", caps[40])
	}
}

func TestDecodeCapMask(t *testing.T) {
	tests := []struct {
		name string
		mask uint64
		want []string
	}{
		{"empty", 0, nil},
		{"chown only", 1, []string{"CAP_CHOWN"}},
		{"net admin and raw", 1<<12 | 1<<13, []string{"CAP_NET_ADMIN", "CAP_NET_RAW"}},
		{"docker default tail", 1 << 27, []string{"CAP_MKNOD"}},
		{"unknown future bit", 1 << 50, []string{"CAP_50"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecodeCapMask(tt.mask); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCapBndErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"no CapBnd line", "Name:\tcat\n"},
		{"non-hex value", "CapBnd:\tnot-a-number\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseCapBnd(strings.NewReader(tt.in)); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// goldenRoute is /proc/net/route from the NAT-mode WSL host: a default route
// via 172.22.80.1 on eth0 plus the on-link 172.22.80.0/20.
const goldenRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	015016AC	0003	0	0	0	00000000	0	0	0
eth0	005016AC	00000000	0001	0	0	0	00F0FFFF	0	0	0
`

func TestParseProcNetRoute(t *testing.T) {
	got, err := ParseProcNetRoute(strings.NewReader(goldenRoute))
	if err != nil {
		t.Fatalf("ParseProcNetRoute: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d routes, want 2", len(got))
	}
	tests := []struct {
		name      string
		idx       int
		iface     string
		isDefault bool
		gateway   uint32
	}{
		{"default route", 0, "eth0", true, 0x015016AC},
		{"on-link subnet", 1, "eth0", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := got[tt.idx]
			if e.Iface != tt.iface {
				t.Errorf("iface = %q, want %q", e.Iface, tt.iface)
			}
			if e.IsDefault() != tt.isDefault {
				t.Errorf("IsDefault = %v, want %v", e.IsDefault(), tt.isDefault)
			}
			if e.Gateway != tt.gateway {
				t.Errorf("gateway = %#x, want %#x", e.Gateway, tt.gateway)
			}
		})
	}
}

func TestParseProcNetRouteMalformed(t *testing.T) {
	got, err := ParseProcNetRoute(strings.NewReader("Iface\tDestination\nshort line\n"))
	if err != nil {
		t.Fatalf("ParseProcNetRoute: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d routes, want 0", len(got))
	}
}

func TestParseSubIDRange(t *testing.T) {
	const golden = `# a comment
lenovo:100000:65536
puru:165536:65536
nobody:0:0
`
	tests := []struct {
		name string
		user string
		want string
	}{
		{"first entry", "lenovo", "100000:65536"},
		{"second entry", "puru", "165536:65536"},
		{"zero range is still an entry", "nobody", "0:0"},
		{"absent user", "root", ""},
		{"comment is not a user", "#", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSubIDRange(strings.NewReader(golden), tt.user)
			if err != nil {
				t.Fatalf("ParseSubIDRange: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseIptablesForwardPolicy(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{
			name: "docker desktop DROP policy",
			in: "-P FORWARD DROP\n" +
				"-N DOCKER\n" +
				"-N DOCKER-ISOLATION-STAGE-1\n" +
				"-A FORWARD -j DOCKER-USER\n" +
				"-A FORWARD -o docker0 -j DOCKER\n",
			want: "DROP",
		},
		{
			name: "clean host",
			in:   "-P FORWARD ACCEPT\n",
			want: "ACCEPT",
		},
		{
			name:    "no policy line",
			in:      "-A FORWARD -j DOCKER-USER\n",
			wantErr: true,
		},
		{
			name:    "empty output",
			in:      "",
			wantErr: true,
		},
		{
			name: "policy for another chain is ignored",
			in:   "-P INPUT DROP\n-P FORWARD ACCEPT\n",
			want: "ACCEPT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseIptablesForwardPolicy(tt.in)
			if ok == tt.wantErr {
				t.Fatalf("ok = %v, wantErr = %v", ok, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseNftForwardPolicy(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{
			name: "drop policy",
			in: "table ip filter {\n" +
				"\tchain FORWARD {\n" +
				"\t\ttype filter hook forward priority filter; policy drop;\n" +
				"\t\tcounter packets 0 bytes 0 jump DOCKER-USER\n" +
				"\t}\n}\n",
			want: "DROP",
		},
		{
			name: "accept policy",
			in:   "\t\ttype filter hook forward priority filter; policy accept;\n",
			want: "ACCEPT",
		},
		{
			name:    "chain has no policy",
			in:      "table ip filter {\n\tchain FORWARD {\n\t}\n}\n",
			wantErr: true,
		},
		{
			name:    "nft error output",
			in:      "Error: No such file or directory\nlist chain ip filter FORWARD\n",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseNftForwardPolicy(tt.in)
			if ok == tt.wantErr {
				t.Fatalf("ok = %v, wantErr = %v", ok, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseControllers(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"wsl 5.15 hybrid: empty", "", nil},
		{"whitespace only", "  \n", nil},
		{"pure v2", "cpuset cpu io memory hugetlb pids rdma misc", []string{"cpuset", "cpu", "io", "memory", "hugetlb", "pids", "rdma", "misc"}},
		{"single", "memory", []string{"memory"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseControllers(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWSLVersionHint(t *testing.T) {
	tests := []struct {
		name     string
		maj, min int
		release  string
		contains string
	}{
		{"legacy 5.15", 5, 15, "5.15.167.4-microsoft-standard-WSL2", "legacy 5.15 generation"},
		{"modern 6.6", 6, 6, "6.6.87.2-microsoft-standard-WSL2", "6.x generation"},
		{"modern 6.18", 6, 18, "6.18.0-microsoft-standard-WSL2", "6.x generation"},
		{"other", 5, 4, "5.4.0-generic", "kernel 5.4.0-generic"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wslVersionHint(tt.maj, tt.min, tt.release)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("hint %q does not contain %q", got, tt.contains)
			}
		})
	}
}

func TestUnescapeMountField(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/mnt/c", "/mnt/c"},
		{`/var/lib/hull\040data`, "/var/lib/hull data"},
		{`a\011b`, "a\tb"},
		{`C:\134`, `C:\`},
		{`trailing\`, `trailing\`},
		{`bad\99x`, `bad\99x`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := unescapeMountField(tt.in); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
