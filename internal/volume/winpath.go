package volume

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// uncAdvice is the exact guidance hull gives when a user hands it a \\wsl$ or
// \\wsl.localhost UNC path. Binding one would route every read and write
// through the Windows 9p/virtiofs file server and straight back into the same
// VM, which is both slow and, for a running container, pointless: the engine
// can already see the Linux path.
const uncAdvice = `hull cannot bind a \\wsl$ path; use the Linux path directly (e.g. /home/you/proj).`

// winDriveRE matches a Windows drive-letter prefix followed by a separator,
// which is the only shape TranslateWindowsPath converts. The separator is
// required so a bare "name:" volume reference is never read as a drive.
var winDriveRE = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

// winDriveOnlyRE matches a bare drive such as "C:", which denotes that drive's
// root directory.
var winDriveOnlyRE = regexp.MustCompile(`^[A-Za-z]:$`)

// wslShareRE matches the forward-slash spelling of the WSL UNC shares, which
// git-bash and PowerShell both produce: //wsl$/Ubuntu/... and
// //wsl.localhost/Ubuntu/...
var wslShareRE = regexp.MustCompile(`(?i)^//(wsl\$|wsl\.localhost)(/|$)`)

// IsWindowsPath reports whether p looks like a Windows path: a drive-letter
// prefix, or a UNC path. The test is purely lexical and touches no filesystem.
func IsWindowsPath(p string) bool {
	return winDriveRE.MatchString(p) || winDriveOnlyRE.MatchString(p) || IsUNCPath(p)
}

// IsUNCPath reports whether p is a Windows UNC path that hull must refuse.
//
// Two leading backslashes are always UNC. Two leading forward slashes are only
// treated as UNC for the WSL shares (//wsl$/... and //wsl.localhost/...),
// because "//var/run/docker.sock" is the well-worn git-bash/MSYS idiom for
// escaping a plain Linux path and refusing it would break real compose files.
func IsUNCPath(p string) bool {
	if len(p) < 2 {
		return false
	}
	if p[0] == '\\' && p[1] == '\\' {
		return true
	}
	return wslShareRE.MatchString(p)
}

// isWSLShare reports whether p names one of the WSL UNC shares, in either slash
// spelling.
func isWSLShare(p string) bool {
	norm := strings.ReplaceAll(p, `\`, "/")
	return wslShareRE.MatchString(norm) || strings.EqualFold(norm, "//wsl$") || strings.EqualFold(norm, "//wsl.localhost")
}

// TranslateWindowsPath maps a Windows host path onto the path the WSL2 VM sees.
//
//	C:\Users\me\proj      -> /mnt/c/Users/me/proj
//	c:/Users/me/proj      -> /mnt/c/Users/me/proj
//	C:\                   -> /mnt/c
//	/mnt/c/Users/me       -> /mnt/c/Users/me   (idempotent)
//	/home/you/proj        -> /home/you/proj    (already a Linux path)
//	//var/run/docker.sock -> /var/run/docker.sock (git-bash escaping)
//
// A UNC path is rejected: \\wsl$\... and \\wsl.localhost\... get the actionable
// message in uncAdvice, any other UNC path gets an equivalent refusal naming
// the reason. A relative path is rejected, because a bind source must be
// unambiguous by the time it reaches the daemon.
//
// NOTE(duplication): internal/bundle exports a helper of the same name for the
// runtime side of the bundle generator. The two must stay byte-identical in
// behaviour. internal/bundle sits above internal/volume in the package
// layering, so bundle's copy should delegate here rather than re-derive the
// rules; if it ever cannot, any change made here must be mirrored there.
func TranslateWindowsPath(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("%w: empty path", ErrInvalidMount)
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: path contains a NUL byte", ErrInvalidMount)
	}
	if isWSLShare(p) {
		return "", fmt.Errorf("%w: %s", ErrUNCPath, uncAdvice)
	}
	if IsUNCPath(p) {
		return "", fmt.Errorf("%w: %q is a UNC path; hull can only bind what the WSL2 VM sees directly - a Linux path, or a Windows drive such as C:\\Users\\you\\proj", ErrUNCPath, p)
	}

	switch {
	case winDriveOnlyRE.MatchString(p):
		return "/mnt/" + strings.ToLower(p[:1]), nil

	case winDriveRE.MatchString(p):
		drive := strings.ToLower(p[:1])
		rest := strings.ReplaceAll(p[2:], `\`, "/")
		return path.Clean("/mnt/" + drive + "/" + strings.TrimPrefix(rest, "/")), nil

	case strings.HasPrefix(p, "/"):
		// Already a Linux path. path.Clean collapses the git-bash "//" prefix
		// and keeps this function idempotent for /mnt/<d>/... paths.
		return path.Clean("/" + strings.TrimLeft(p, "/")), nil

	default:
		return "", fmt.Errorf("%w: %q is not absolute; a bind source must be an absolute path (e.g. /home/you/proj or C:\\Users\\you\\proj)", ErrInvalidMount, p)
	}
}
