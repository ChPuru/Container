package localproxy

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
)

// maxSuggestions bounds the "did you mean" list on the 404 page.
const maxSuggestions = 3

// suggestDistance is the edit distance at which a registered name is offered
// as a correction for an unknown one.
const suggestDistance = 2

// pageData is the model behind the 404, the index and the 502.
type pageData struct {
	Title    string
	Host     string
	Domain   string
	Target   string
	Reason   string
	Routes   []Route
	Suggest  []string
	HostFile bool
}

// writeIndex answers a request for the bare domain with the route list. A user
// who types http://localhost/ is asking what is running; telling them is
// strictly more useful than a 404.
func (p *Proxy) writeIndex(w http.ResponseWriter, r *http.Request) {
	d := pageData{
		Title:  "hull",
		Host:   normalizeHost(r.Host),
		Domain: p.domain,
		Routes: p.Routes(),
	}
	p.writePage(w, r, http.StatusOK, d)
}

// writeNotFound answers an unroutable Host with a 404 that lists the routes
// that do exist. The listing is the entire point: "not found" alone cannot
// distinguish a typo from a stopped container from a proxy that never learned
// about the container at all.
func (p *Proxy) writeNotFound(w http.ResponseWriter, r *http.Request, host string) {
	routes := p.Routes()
	d := pageData{
		Title:    "no route for " + host,
		Host:     host,
		Domain:   p.domain,
		Routes:   routes,
		Suggest:  suggest(host, routes),
		HostFile: strings.HasSuffix(host, "."+p.domain) || host == p.domain,
	}
	if len(routes) == 0 {
		d.Reason = "hull is not routing any names yet. Start a container that publishes an HTTP port."
	} else {
		d.Reason = fmt.Sprintf("No container answers for %q.", host)
	}
	p.writePage(w, r, http.StatusNotFound, d)
}

// writeGatewayError answers an upstream failure with the name, the address it
// resolved to and the usual cause.
func (p *Proxy) writeGatewayError(w http.ResponseWriter, r *http.Request, host, target string, err error) {
	d := pageData{
		Title:  "upstream unreachable",
		Host:   host,
		Domain: p.domain,
		Target: target,
		Reason: fmt.Sprintf("%s is routed to %s, but the connection failed: %v. "+
			"The container is usually stopped, still starting, or listening on a different port inside the container.",
			host, target, err),
		Routes: p.Routes(),
	}
	p.writePage(w, r, http.StatusBadGateway, d)
}

func (p *Proxy) writePage(w http.ResponseWriter, r *http.Request, status int, d pageData) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if wantsHTML(r) {
		h.Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		if err := pageTmpl.Execute(w, d); err != nil {
			p.logf("localproxy: render page: %v", err)
		}
		return
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(renderText(d)))
}

// wantsHTML reports whether the client actually asked for HTML. curl sends
// "*/*" and gets the plain-text rendering, which is the one you can read in a
// terminal; a browser sends text/html and gets the page.
func wantsHTML(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		media, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(media, "text/html") {
			return true
		}
	}
	return false
}

// renderText is the terminal rendering of a page.
func renderText(d pageData) string {
	var b strings.Builder
	fmt.Fprintf(&b, "hull: %s\n\n", d.Title)
	if d.Reason != "" {
		fmt.Fprintf(&b, "%s\n\n", d.Reason)
	}
	if len(d.Suggest) > 0 {
		fmt.Fprintf(&b, "Did you mean: %s\n\n", strings.Join(d.Suggest, ", "))
	}
	if len(d.Routes) == 0 {
		b.WriteString("Routes: none registered.\n")
	} else {
		b.WriteString("Routes hull is serving right now:\n")
		for _, rt := range d.Routes {
			fmt.Fprintf(&b, "  %-32s -> %s\n", rt.Hostnames[0], rt.Target)
			for _, alias := range rt.Hostnames[1:] {
				fmt.Fprintf(&b, "  %-32s    (alias of %s)\n", alias, rt.Hostnames[0])
			}
		}
	}
	if d.HostFile {
		b.WriteString("\n")
		b.WriteString(hostsFileNote)
		b.WriteString("\n")
	}
	return b.String()
}

// hostsFileNote is the Windows-resolver advice, in the one place a user is
// guaranteed to be looking when the name did not work.
const hostsFileNote = `If the name did not resolve at all on Windows: Windows does not special-case
*.localhost the way Linux does. Either add a line per name to
%SystemRoot%\System32\drivers\etc\hosts (as Administrator):

    127.0.0.1 <name>.localhost

or skip resolution entirely and send the Host header yourself:

    curl -H 'Host: <name>.localhost' http://127.0.0.1/

Run 'hull doctor' to have hull check this for you.`

// suggest returns the registered names closest to an unknown host.
func suggest(host string, routes []Route) []string {
	label, _, _ := strings.Cut(host, ".")
	if label == "" {
		return nil
	}
	type scored struct {
		name string
		d    int
	}
	var out []scored
	for _, rt := range routes {
		best := -1
		for _, h := range rt.Hostnames {
			cand, _, _ := strings.Cut(h, ".")
			d := editDistance(label, cand)
			if strings.HasPrefix(cand, label) || strings.HasPrefix(label, cand) {
				d = min(d, 1)
			}
			if best < 0 || d < best {
				best = d
			}
		}
		if best >= 0 && best <= suggestDistance {
			out = append(out, scored{rt.Hostnames[0], best})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].d != out[j].d {
			return out[i].d < out[j].d
		}
		return out[i].name < out[j].name
	})
	names := make([]string, 0, maxSuggestions)
	for _, s := range out {
		if len(names) == maxSuggestions {
			break
		}
		names = append(names, s.name)
	}
	return names
}

// editDistance is the Levenshtein distance between a and b, used only to turn
// a typo into a suggestion.
func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}

// pageTmpl renders every hull-generated page. It is self-contained: the proxy
// must be able to explain itself with no network and no assets.
var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>hull — {{.Title}}</title>
<style>
:root { color-scheme: light dark; }
body { margin: 0; padding: 2rem 1.25rem; font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 46rem; margin: 0 auto; }
h1 { font-size: 1.35rem; margin: 0 0 .35rem; }
p.sub { margin: 0 0 1.5rem; opacity: .75; }
table { border-collapse: collapse; width: 100%; font-size: .93rem; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid rgba(128,128,128,.28); }
th { font-weight: 600; opacity: .7; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .88rem; }
pre { background: rgba(128,128,128,.12); padding: .75rem .9rem; border-radius: .4rem; overflow-x: auto; }
.alias { opacity: .65; font-size: .85rem; }
.none { opacity: .7; font-style: italic; }
a { color: inherit; }
section { margin-top: 1.75rem; }
</style></head>
<body><main>
<h1>{{.Title}}</h1>
{{if .Reason}}<p class="sub">{{.Reason}}</p>{{end}}
{{if .Suggest}}<p>Did you mean
{{range $i, $s := .Suggest}}{{if $i}}, {{end}}<a href="http://{{$s}}/">{{$s}}</a>{{end}}?</p>{{end}}
<section>
<h2 style="font-size:1rem">Routes hull is serving</h2>
{{if .Routes}}
<table><thead><tr><th>Name</th><th>Goes to</th></tr></thead><tbody>
{{range .Routes}}<tr>
<td><a href="http://{{index .Hostnames 0}}/">{{index .Hostnames 0}}</a>
{{range $i, $h := .Hostnames}}{{if $i}}<div class="alias">{{$h}}</div>{{end}}{{end}}</td>
<td><code>{{.Target}}</code></td>
</tr>{{end}}
</tbody></table>
{{else}}<p class="none">No names are registered yet. Start a container that publishes an HTTP port.</p>{{end}}
</section>
{{if .HostFile}}<section>
<h2 style="font-size:1rem">If the name did not resolve on Windows</h2>
<p>Windows does not special-case <code>*.{{.Domain}}</code> the way Linux does. Either add one line
per name to <code>%SystemRoot%\System32\drivers\etc\hosts</code> as Administrator:</p>
<pre>127.0.0.1 {{.Host}}</pre>
<p>or skip resolution entirely and send the Host header yourself:</p>
<pre>curl -H 'Host: {{.Host}}' http://127.0.0.1/</pre>
<p>Run <code>hull doctor</code> to have hull check this for you.</p>
</section>{{end}}
</main></body></html>
`))
