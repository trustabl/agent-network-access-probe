package policy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// DenyList is a set of hostnames/IPs and CIDR ranges that must never appear
// in a generated draft's allow list, regardless of what was observed.
type DenyList struct {
	hosts map[string]bool // exact hostname/IP matches, lowercased, trailing dot trimmed
	cidrs []*net.IPNet
}

// NewDenyList returns an empty DenyList.
func NewDenyList() *DenyList {
	return &DenyList{hosts: map[string]bool{}}
}

// normalizeHost lowercases and strips a trailing FQDN dot for consistent matching.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// AddHost adds an exact hostname or IP match to the deny list.
func (d *DenyList) AddHost(host string) {
	if d.hosts == nil {
		d.hosts = map[string]bool{}
	}
	d.hosts[normalizeHost(host)] = true
}

// AddCIDR adds a denied IP range to the deny list.
func (d *DenyList) AddCIDR(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	d.cidrs = append(d.cidrs, ipNet)
	return nil
}

// Match reports whether host (a hostname or IP-literal string, as it appears
// in an AllowedEndpoint) is denied: exact hostname/IP match, or containment
// in any denied CIDR.
func (d *DenyList) Match(host string) bool {
	if d == nil {
		return false
	}
	norm := normalizeHost(host)
	if d.hosts[norm] {
		return true
	}
	ip := net.ParseIP(norm)
	if ip == nil {
		return false
	}
	for _, cidr := range d.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// BuiltinDenyList returns the always-on deny set: cloud metadata endpoints
// and link-local ranges. Not user-configurable — merged into every run
// regardless of --deny-list.
func BuiltinDenyList() *DenyList {
	d := NewDenyList()
	d.AddHost("169.254.169.254")          // cloud metadata IP — AWS/Azure/GCP/OCI all use this
	d.AddHost("metadata.google.internal") // GCP metadata hostname
	// IPv4 link-local — already covers the metadata IP above, kept explicit
	// per the spec's literal wording ("169.254.169.254, metadata.google.internal, link-local").
	_ = d.AddCIDR("169.254.0.0/16")
	_ = d.AddCIDR("fe80::/10") // IPv6 link-local
	return d
}

// LoadDenyList reads a plain-text deny file: one hostname/IP or CIDR per
// line, '#'-prefixed comments and blank lines skipped. A line containing '/'
// is parsed as a CIDR; a malformed CIDR line is a hard error — a deny list
// that silently doesn't load is a worse failure mode than refusing to run.
func LoadDenyList(path string) (*DenyList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open deny list: %w", err)
	}
	defer f.Close()

	d := NewDenyList()
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			if err := d.AddCIDR(line); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, lineNum, err)
			}
			continue
		}
		d.AddHost(line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read deny list: %w", err)
	}
	return d, nil
}

// Merge combines multiple deny lists into one new DenyList.
func Merge(lists ...*DenyList) *DenyList {
	d := NewDenyList()
	for _, l := range lists {
		if l == nil {
			continue
		}
		for h := range l.hosts {
			d.hosts[h] = true
		}
		d.cidrs = append(d.cidrs, l.cidrs...)
	}
	return d
}
