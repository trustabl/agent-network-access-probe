package policy

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// GapKind classifies a single policy diff entry.
type GapKind string

const (
	GapCorrect         GapKind = "correct"
	GapOverPermissive  GapKind = "over_permissive"
	GapUnderPermissive GapKind = "under_permissive"
)

// GapEntry is one finding from the policy diff.
type GapEntry struct {
	Kind     GapKind
	Endpoint AllowedEndpoint
	Detail   string
}

// Diff parses the existing OpenShell policy at existingPath, compares its outbound
// network_policies against the generated least-privilege policy, and returns gap entries.
func Diff(existingPath string, generated *PolicyDoc) ([]GapEntry, error) {
	data, err := os.ReadFile(existingPath)
	if err != nil {
		return nil, fmt.Errorf("read existing policy: %w", err)
	}
	var existing PolicyDoc
	if err := yaml.Unmarshal(data, &existing); err != nil {
		return nil, fmt.Errorf("parse existing policy: %w", err)
	}

	existingOutbound := existing.NetworkPolicies.Outbound
	generatedOutbound := generated.NetworkPolicies.Outbound

	// Build lookup maps keyed by host (port/protocol differences are secondary).
	existingByHost := map[string]AllowedEndpoint{}
	for _, ep := range existingOutbound {
		existingByHost[ep.Host] = ep
	}
	generatedByHost := map[string]AllowedEndpoint{}
	for _, ep := range generatedOutbound {
		generatedByHost[ep.Host] = ep
	}

	var gaps []GapEntry

	// Entries in the existing policy.
	for _, ep := range existingOutbound {
		if _, needed := generatedByHost[ep.Host]; needed {
			gaps = append(gaps, GapEntry{
				Kind:     GapCorrect,
				Endpoint: ep,
				Detail:   "tool uses this endpoint, policy allows it",
			})
		} else {
			gaps = append(gaps, GapEntry{
				Kind:     GapOverPermissive,
				Endpoint: ep,
				Detail:   "policy allows this but tool never calls it",
			})
		}
	}

	// Entries needed by the tool but missing from the existing policy.
	for _, ep := range generatedOutbound {
		if _, allowed := existingByHost[ep.Host]; !allowed {
			gaps = append(gaps, GapEntry{
				Kind:     GapUnderPermissive,
				Endpoint: ep,
				Detail:   "tool calls this but policy does not allow it",
			})
		}
	}

	return gaps, nil
}

// PrintDiff renders gap entries to w. Style functions are passed in from the caller
// (typically main.go) so this package does not import lipgloss.
// styleOver = red, styleUnder = yellow, styleOk = green.
func PrintDiff(w io.Writer, gaps []GapEntry, styleOver, styleUnder, styleOk func(string) string) {
	if len(gaps) == 0 {
		fmt.Fprintln(w, styleOk("  ✓ No policy gaps detected"))
		return
	}
	for _, g := range gaps {
		label := fmt.Sprintf("%s:%d", g.Endpoint.Host, g.Endpoint.Port)
		switch g.Kind {
		case GapCorrect:
			fmt.Fprintf(w, "  %s  %-45s  %s\n",
				styleOk("✓"), label, styleOk(g.Detail))
		case GapOverPermissive:
			fmt.Fprintf(w, "  %s  %-45s  %s\n",
				styleOver("✗"), label, styleOver(g.Detail))
		case GapUnderPermissive:
			fmt.Fprintf(w, "  %s  %-45s  %s\n",
				styleUnder("⚠"), label, styleUnder(g.Detail))
		}
	}
}
