package policy

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/trustabl/trustabl-probe/internal/sandbox"
)

var reURLLiteral = regexp.MustCompile(`https?://[^"' \t\n\\]+`)

// reOutboundDecl matches "// Outbound: host:port" doc comments written by the fixer.
var reOutboundDecl = regexp.MustCompile(`(?i)//\s*[Oo]utbound:\s*([a-zA-Z0-9._-]+(?::\d+)?)`)

// AllowedEndpoint is a single allowed outbound network destination.
type AllowedEndpoint struct {
	Host     string `yaml:"host"     json:"host"`
	Port     int    `yaml:"port,omitempty" json:"port,omitempty"`
	Protocol string `yaml:"protocol" json:"protocol"`
	// Source is set only when an --allow-list/--platform-allow-list entry
	// matched this endpoint ("declared" or "platform"). Never serialized
	// into network_policies.draft.yaml (yaml:"-") — that file stays exactly
	// what OpenShell consumes, no Trustabl-only fields. Only appears in
	// probe.profile.json.
	Source AllowSource `yaml:"-" json:"source,omitempty"`
}

// FilesystemPolicy mirrors the OpenShell filesystem_policy block.
type FilesystemPolicy struct {
	ReadOnly  []string `yaml:"read_only,flow"`
	ReadWrite []string `yaml:"read_write,flow"`
}

// LandlockPolicy mirrors the OpenShell landlock block.
type LandlockPolicy struct {
	Compatibility string `yaml:"compatibility"`
}

// ProcessPolicy mirrors the OpenShell process block.
type ProcessPolicy struct {
	RunAsUser  string `yaml:"run_as_user"`
	RunAsGroup string `yaml:"run_as_group"`
}

// OutboundPolicies holds the outbound network allow-list.
// Using a named struct (not map[string][]AllowedEndpoint) so yaml.v3
// unmarshals it reliably via struct field tags.
type OutboundPolicies struct {
	Outbound []AllowedEndpoint `yaml:"outbound"`
}

// PolicyDoc is the full OpenShell policy document.
type PolicyDoc struct {
	Version          int              `yaml:"version"`
	FilesystemPolicy FilesystemPolicy `yaml:"filesystem_policy"`
	Landlock         LandlockPolicy   `yaml:"landlock"`
	Process          ProcessPolicy    `yaml:"process"`
	NetworkPolicies  OutboundPolicies `yaml:"network_policies"`
}

// Generate builds a least-privilege PolicyDoc from analyzer/sandbox findings.
// srcContents maps file path → raw source text for URL literal extraction.
// deny may be nil (no filtering); denied endpoints are never written into the
// generated allow list. allow may also be nil (no declared/platform
// constraint — every non-denied observed endpoint is allowed, matching
// today's behavior); when set, an observed endpoint must also match allow to
// be written into the draft — see ExtractToolEndpoints.
func Generate(candidates []sandbox.Candidate, srcContents map[string]string, deny *DenyList, allow *AllowList) *PolicyDoc {
	endpoints := extractEndpoints(candidates, srcContents, deny, allow)
	return &PolicyDoc{
		Version: 1,
		FilesystemPolicy: FilesystemPolicy{
			ReadOnly:  []string{"/usr", "/lib", "/etc"},
			ReadWrite: []string{"/sandbox", "/tmp"},
		},
		Landlock: LandlockPolicy{Compatibility: "best_effort"},
		Process: ProcessPolicy{
			RunAsUser:  "sandbox",
			RunAsGroup: "sandbox",
		},
		NetworkPolicies: OutboundPolicies{Outbound: endpoints},
	}
}

// WritePolicy marshals doc to YAML and writes it to destDir/network_policies.draft.yaml.
func WritePolicy(doc *PolicyDoc, destDir string) error {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(destDir, "network_policies.draft.yaml"), data, 0o644)
}

// ExtractToolEndpoints returns three lists for a single tool: endpoints safe
// to allow, endpoints that matched deny (excluded from allowed, never
// written into a generated draft's allow list), and endpoints that were
// observed but matched neither deny nor an active allow list (also excluded
// from allowed — "do not auto-add", per the product spec's list-evaluation
// rules). deny may be nil (nothing denied). allow may also be nil, in which
// case every non-denied endpoint is allowed exactly as before Slice 6
// (notInAllow stays empty and Source stays unset) — allow only starts
// constraining what's auto-added once a caller actually supplies one.
func ExtractToolEndpoints(candidates []sandbox.Candidate, src string, deny *DenyList, allow *AllowList) (allowed, denied, notInAllow []AllowedEndpoint) {
	type hostKey struct{ host, protocol string }
	seen := map[hostKey]bool{}

	// route classifies one candidate endpoint against deny then allow.
	route := func(host string, port int) {
		ep := AllowedEndpoint{Host: host, Protocol: "tcp", Port: port}
		if deny.Match(host) {
			denied = append(denied, ep)
			return
		}
		if allow == nil {
			allowed = append(allowed, ep)
			return
		}
		if src, matched := allow.Match(host); matched {
			ep.Source = src
			allowed = append(allowed, ep)
			return
		}
		notInAllow = append(notInAllow, ep)
	}

	add := func(rawURL string) {
		u, err := url.Parse(strings.TrimRight(rawURL, ").,;"))
		if err != nil || u.Hostname() == "" {
			return
		}
		host := u.Hostname()
		// Protocol here is the transport protocol OpenShell's network_policies
		// schema expects (tcp/udp), not the URL scheme — everything Probe
		// observes today is TCP. Scheme still selects the default port.
		scheme := u.Scheme
		if scheme == "" {
			scheme = "https"
		}
		k := hostKey{host, "tcp"}
		if seen[k] {
			return
		}
		seen[k] = true
		port := 443
		if scheme == "http" {
			port = 80
		}
		route(host, port)
	}

	// Primary source: URL string literals in source code.
	for _, m := range reURLLiteral.FindAllString(src, -1) {
		add(m)
	}
	// Also pick up // Outbound: host:port declarations written by the fixer.
	for _, m := range reOutboundDecl.FindAllStringSubmatch(src, -1) {
		hostPort := m[1]
		host, portStr, hasSep := strings.Cut(hostPort, ":")
		port := 443
		if hasSep {
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
		}
		k := hostKey{host, "tcp"}
		if seen[k] {
			continue
		}
		seen[k] = true
		route(host, port)
	}

	// Secondary: evidence detail/rawline strings (catches sandbox log events).
	for _, c := range candidates {
		for _, e := range c.Evidence {
			for _, m := range reURLLiteral.FindAllString(e.RawLine+" "+e.Detail, -1) {
				add(m)
			}
		}
	}

	return allowed, denied, notInAllow
}

// extractEndpoints collects unique AllowedEndpoint values across the whole
// run. sandbox.Candidate carries no per-file attribution today, so this
// concatenates every file's source text into one blob and reuses
// ExtractToolEndpoints against the full candidate list — safe because both
// scan passes are plain regex pattern matches, not per-line/per-file
// structured parsing, so concatenation doesn't change what's found. The
// denied/notInAllow returns are discarded here — finding construction
// happens once, in main.go, not duplicated across every caller of this
// primitive.
func extractEndpoints(candidates []sandbox.Candidate, srcContents map[string]string, deny *DenyList, allow *AllowList) []AllowedEndpoint {
	var allSrc strings.Builder
	for _, src := range srcContents {
		allSrc.WriteString(src)
		allSrc.WriteString("\n")
	}
	allowed, _, _ := ExtractToolEndpoints(candidates, allSrc.String(), deny, allow)
	return allowed
}
