package localca

import (
	"fmt"
	"strings"
)

// WindowsCertPath is the canonical location of the root on a Windows host that
// is using hull's default data directory. It is spelled with the environment
// variable rather than an expanded path because that is what the user has to
// type, and because the CLI may be printing the hint from inside WSL where the
// Windows-side path is not directly observable.
const WindowsCertPath = `%LOCALAPPDATA%\hull\ca\hull-ca.pem`

// InstallHint returns the exact commands that trust hull's root, one per
// platform, plus where the root actually lives on this host.
//
// hull prints this once — when the proxy first starts with a freshly generated
// root — and then never mentions it again. It does not, and will not, modify a
// trust store itself: that is the user's decision to make, and a tool that
// silently installs a signing root into the system store is indistinguishable
// from malware doing the same thing. Until the user runs one of these, HTTPS on
// <name>.localhost still works; the browser simply shows its untrusted-root
// warning, and plain HTTP on port 80 is unaffected.
//
// The output is deterministic, so callers may diff or test it.
func (c *CA) InstallHint() string {
	var b strings.Builder
	w := func(format string, args ...any) {
		fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}

	w("hull generated a local root CA for *.localhost HTTPS.")
	w("It lives at %s (private key: %s).", c.certPath, c.keyPath)
	w("hull will not install it into any trust store for you. To trust it yourself, once:")
	w("")
	w("  Windows (current user store; also covers Chrome and Edge):")
	w("    certutil -addstore -user Root %s", WindowsCertPath)
	w("")
	w("  Windows, undo:")
	w("    certutil -delstore -user Root \"hull local CA\"")
	w("")
	w("  Linux (Debian/Ubuntu):")
	w("    sudo cp %s /usr/local/share/ca-certificates/hull-ca.crt", c.certPath)
	w("    sudo update-ca-certificates")
	w("")
	w("  Linux (Fedora/RHEL/Arch):")
	w("    sudo cp %s /etc/pki/ca-trust/source/anchors/hull-ca.pem", c.certPath)
	w("    sudo update-ca-trust extract")
	w("")
	w("  Firefox and Thunderbird keep their own store:")
	w("    certutil -A -n \"hull local CA\" -t \"C,,\" -i %s \\", c.certPath)
	w("      -d sql:$HOME/.mozilla/firefox/<profile>")
	w("    (certutil here is libnss3-tools, not the Windows program of the same name.)")
	w("")
	w("  curl, one-off, without trusting anything:")
	w("    curl --cacert %s https://<name>.localhost/", c.certPath)

	return strings.TrimRight(b.String(), "\n")
}
