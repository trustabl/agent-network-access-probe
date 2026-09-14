// Package profile builds probe.profile.json — the per-tool egress table and
// scan metadata that accompanies the unsigned network_policies.draft.yaml.
package profile

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/trustabl/probe/internal/policy"
	"github.com/trustabl/probe/internal/sandbox"
)

// ToolInput is one tool's scan results, scoped to that tool alone — the
// caller is responsible for grouping candidates/source text per tool before
// calling Build (main.go's allFiles/fileCandidates already does this).
type ToolInput struct {
	Path       string
	Language   string
	Candidates []sandbox.Candidate
	Src        string
	// HarnessID is the sandbox.ScanResult.SandboxID for this tool's run.
	// Empty when the tool was only statically analyzed (no --sandbox).
	HarnessID string
	// CacheHit is true when this tool's sandbox result was reused from the
	// per-tool cache (internal/cache) rather than freshly executed.
	CacheHit bool
}

// ToolProfile is one tool's entry in the per-tool egress table.
type ToolProfile struct {
	Path          string                   `json:"path"`
	Language      string                   `json:"language,omitempty"`
	HarnessID     string                   `json:"harness_id,omitempty"`
	CacheHit      bool                     `json:"cache_hit"`
	Egress        []policy.AllowedEndpoint `json:"egress"`
	FindingsCount int                      `json:"findings_count"`
}

// Profile is probe.profile.json: class, grant set, and per-tool egress for
// one Probe run. Always unsigned — this is evidence, not the enforced or
// signed artifact (that's network_policies.draft.yaml and, downstream,
// Trustabl Policy).
//
// tool_versions, env_profile, and credential_profile_id from the product
// contract are intentionally omitted: nothing in Probe today detects tool
// versions, and env/credential profile identity is folded into the cache
// key's fixture-content hash (internal/cache) rather than modeled as a
// separate named field — see that package's doc comment. Adding placeholder
// values for them now would misrepresent this artifact as more complete
// than it is.
type Profile struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	// Class is empty for a plain --source run; populated once class-level
	// grant-set input exists.
	Class    string   `json:"class,omitempty"`
	Source   string   `json:"source"`
	GrantSet []string `json:"grant_set"`
	// GrantSetHash is a deterministic hash over GrantSet (order-independent
	// — see hashGrantSet) so a downstream consumer can detect drift between
	// the class YAML it holds and the class YAML that produced this draft
	// without diffing the full path list by hand. Empty for zero tools.
	GrantSetHash string        `json:"grant_set_hash,omitempty"`
	Tools        []ToolProfile `json:"tools"`
}

// Build assembles a Profile from per-tool scan inputs. deny may be nil (no
// filtering); when set, denied endpoints are excluded from every tool's
// Egress — probe.profile.json's egress table stays consistent with the
// generated policy draft, which also never allows a denied destination.
// allow may also be nil (no declared/platform constraint); when set, an
// observed endpoint must also match allow to appear in Egress, and matching
// entries carry their Source ("declared" or "platform").
func Build(sourcePath, class string, inputs []ToolInput, deny *policy.DenyList, allow *policy.AllowList) *Profile {
	p := &Profile{
		SchemaVersion: "1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Class:         class,
		Source:        sourcePath,
	}
	for _, in := range inputs {
		p.GrantSet = append(p.GrantSet, in.Path)
		egress, _, _ := policy.ExtractToolEndpoints(in.Candidates, in.Src, deny, allow)
		if egress == nil {
			egress = []policy.AllowedEndpoint{}
		}
		p.Tools = append(p.Tools, ToolProfile{
			Path:          in.Path,
			Language:      in.Language,
			HarnessID:     in.HarnessID,
			CacheHit:      in.CacheHit,
			Egress:        egress,
			FindingsCount: len(in.Candidates),
		})
	}
	p.GrantSetHash = hashGrantSet(p.GrantSet)
	return p
}

// hashGrantSet returns a deterministic hex-encoded sha256 over paths,
// sorted so member order in the class YAML never changes the hash — only
// the actual member set does. Empty when there's nothing to hash.
func hashGrantSet(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	sorted := append([]string{}, paths...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, p := range sorted {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Write marshals p to indented JSON and writes it to destDir/probe.profile.json.
func Write(p *Profile, destDir string) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(destDir, "probe.profile.json"), data, 0o644)
}
