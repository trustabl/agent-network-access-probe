package policy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// AllowSource identifies which source declared an allow-list entry.
type AllowSource string

const (
	SourceDeclared AllowSource = "declared"
	SourcePlatform AllowSource = "platform"
)

// allowSuffix is a wildcard "*.example.com" entry — matches any host that
// ends with the suffix (including the leading dot).
type allowSuffix struct {
	suffix string
	source AllowSource
}

type allowCIDR struct {
	net    *net.IPNet
	source AllowSource
}

// AllowList is a set of hostnames/IPs, wildcard suffixes, and CIDR ranges
// that a customer or platform has declared safe to allow — the "declared"
// and "platform" sources from the product spec's list-evaluation rules.
// Unlike DenyList, there is no built-in AllowList: platform must-reach
// endpoints (NIM, IdP, inference router) are deployment-specific and unknown
// to this repo, so an AllowList only ever contains what a caller loads.
type AllowList struct {
	hosts    map[string]AllowSource // exact hostname/IP match
	suffixes []allowSuffix
	cidrs    []allowCIDR
}

// NewAllowList returns an empty AllowList.
func NewAllowList() *AllowList {
	return &AllowList{hosts: map[string]AllowSource{}}
}

// AddHost adds an exact hostname or IP match, tagged with its source.
func (a *AllowList) AddHost(host string, source AllowSource) {
	if a.hosts == nil {
		a.hosts = map[string]AllowSource{}
	}
	a.hosts[normalizeHost(host)] = source
}

// AddWildcardSuffix adds a "*.example.com"-style entry. suffix must start
// with "*.". Matches any host ending in the suffix (dot included).
func (a *AllowList) AddWildcardSuffix(suffix string, source AllowSource) {
	trimmed := strings.TrimPrefix(normalizeHost(suffix), "*")
	a.suffixes = append(a.suffixes, allowSuffix{suffix: trimmed, source: source})
}

// AddCIDR adds an allowed IP range, tagged with its source.
func (a *AllowList) AddCIDR(cidr string, source AllowSource) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	a.cidrs = append(a.cidrs, allowCIDR{net: ipNet, source: source})
	return nil
}

// Match reports whether host is allowed and, if so, by which source. Checks
// exact host match, then wildcard suffix, then CIDR containment. Nil-safe.
func (a *AllowList) Match(host string) (source AllowSource, matched bool) {
	if a == nil {
		return "", false
	}
	norm := normalizeHost(host)
	if src, ok := a.hosts[norm]; ok {
		return src, true
	}
	for _, s := range a.suffixes {
		if strings.HasSuffix(norm, s.suffix) {
			return s.source, true
		}
	}
	ip := net.ParseIP(norm)
	if ip == nil {
		return "", false
	}
	for _, c := range a.cidrs {
		if c.net.Contains(ip) {
			return c.source, true
		}
	}
	return "", false
}

// BroadEntries returns every loaded entry considered overly permissive: a
// bare "*" wildcard suffix (matches every host), a CIDR of /7 or wider
// (0.0.0.0/0 included — practically "all addresses"), or a wildcard suffix
// with two or fewer dot-separated labels (e.g. "*.amazonaws.com", "*.com").
// The label-count check is a structural heuristic — a short/generic suffix
// covers a huge multi-tenant zone — rather than a hardcoded list of cloud
// vendor domains, so it catches the spec's own example (*.amazonaws.com)
// without needing to enumerate providers (and inevitably going stale).
func (a *AllowList) BroadEntries() []string {
	if a == nil {
		return nil
	}
	var broad []string
	for _, s := range a.suffixes {
		labels := strings.Split(strings.Trim(s.suffix, "."), ".")
		if len(labels) <= 2 {
			broad = append(broad, "*"+s.suffix)
		}
	}
	for _, c := range a.cidrs {
		ones, bits := c.net.Mask.Size()
		if bits > 0 && ones <= 7 {
			broad = append(broad, c.net.String())
		}
	}
	return broad
}

// LoadAllowList reads a plain-text allow file: one entry per line — exact
// host/IP, "*.suffix" wildcard, or CIDR — '#'-prefixed comments and blank
// lines skipped, every entry tagged with source. A line containing '/' is
// parsed as a CIDR; a malformed CIDR line is a hard error, matching
// LoadDenyList's fail-fast convention.
func LoadAllowList(path string, source AllowSource) (*AllowList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open allow list: %w", err)
	}
	defer f.Close()

	a := NewAllowList()
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*.") || line == "*" {
			a.AddWildcardSuffix(line, source)
			continue
		}
		if strings.Contains(line, "/") {
			if err := a.AddCIDR(line, source); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, lineNum, err)
			}
			continue
		}
		a.AddHost(line, source)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read allow list: %w", err)
	}
	return a, nil
}

// MergeAllow combines multiple allow lists into one new AllowList.
func MergeAllow(lists ...*AllowList) *AllowList {
	a := NewAllowList()
	for _, l := range lists {
		if l == nil {
			continue
		}
		for h, src := range l.hosts {
			a.hosts[h] = src
		}
		a.suffixes = append(a.suffixes, l.suffixes...)
		a.cidrs = append(a.cidrs, l.cidrs...)
	}
	return a
}
