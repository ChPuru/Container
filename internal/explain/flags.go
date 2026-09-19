package explain

import "strings"

// cloneFlagNames maps every spelling hull uses for a namespace - the
// runtime-spec type, the CLI's short form and the /proc/<pid>/ns file name -
// onto the CLONE_NEW* constant the kernel is actually passed.
//
// The table is deliberately in this package rather than behind a build tag:
// explain renders flags, it never calls clone3, so it must build on Windows
// alongside the rest of the hull CLI.
var cloneFlagNames = map[string]string{
	"user":    "CLONE_NEWUSER",
	"mount":   "CLONE_NEWNS",
	"mnt":     "CLONE_NEWNS",
	"ns":      "CLONE_NEWNS",
	"pid":     "CLONE_NEWPID",
	"net":     "CLONE_NEWNET",
	"network": "CLONE_NEWNET",
	"uts":     "CLONE_NEWUTS",
	"ipc":     "CLONE_NEWIPC",
	"cgroup":  "CLONE_NEWCGROUP",
	"time":    "CLONE_NEWTIME",
}

// CloneFlags renders a namespace set as the CLONE_NEW* expression clone3(2) or
// setns(2) is really called with, e.g.
//
//	CloneFlags("user", "mnt", "pid", "net") ==
//		"CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET"
//
// Names are matched case-insensitively against every spelling hull uses for a
// namespace. A name that is not a namespace - a CLONE_* constant the caller
// already spelled out, say - is passed through unchanged, so a call site can
// mix the two. Duplicates are dropped and the caller's order is preserved,
// because the order a trace shows should be the order the caller wrote.
//
// An empty set renders as "0", which is what an empty flag word is.
func CloneFlags(names ...string) string {
	if len(names) == 0 {
		return "0"
	}
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		flag, ok := cloneFlagNames[strings.ToLower(n)]
		if !ok {
			flag = n
		}
		if _, dup := seen[flag]; dup {
			continue
		}
		seen[flag] = struct{}{}
		out = append(out, flag)
	}
	if len(out) == 0 {
		return "0"
	}
	return strings.Join(out, "|")
}
