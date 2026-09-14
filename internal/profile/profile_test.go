package profile

import (
	"testing"

	"github.com/trustabl/probe/internal/policy"
	"github.com/trustabl/probe/internal/sandbox"
)

// TestBuild_PerToolEgressTable models an NVIDIA-shaped example close to
// demo/research-assistant/tool.py: one tool that calls a known API and has a
// single runtime finding. Asserts the per-tool egress table this slice adds
// is populated correctly and per-tool (not globally unioned/attributed).
func TestBuild_PerToolEgressTable(t *testing.T) {
	inputs := []ToolInput{
		{
			Path:     "research-assistant/tool.py",
			Language: "python",
			Src:      `// Outbound: api.perplexity.ai:443`,
			Candidates: []sandbox.Candidate{
				{Title: "Unbounded tool output", Severity: "warning"},
			},
			HarnessID: "autofix-1234567890",
		},
		{
			Path:      "go-fetcher/tool.go",
			Language:  "go",
			Src:       `// Outbound: api.marketdata.io:443`,
			HarnessID: "",
		},
	}

	p := Build("./demo", "", inputs, nil, nil)

	if p.SchemaVersion != "1" {
		t.Errorf("SchemaVersion = %q, want %q", p.SchemaVersion, "1")
	}
	if p.Source != "./demo" {
		t.Errorf("Source = %q, want %q", p.Source, "./demo")
	}
	if p.Class != "" {
		t.Errorf("Class = %q, want empty (no --class support today)", p.Class)
	}
	if len(p.GrantSet) != 2 {
		t.Fatalf("len(GrantSet) = %d, want 2: %+v", len(p.GrantSet), p.GrantSet)
	}
	if len(p.Tools) != 2 {
		t.Fatalf("len(Tools) = %d, want 2", len(p.Tools))
	}

	tool1 := p.Tools[0]
	if tool1.Path != "research-assistant/tool.py" {
		t.Errorf("Tools[0].Path = %q, want %q", tool1.Path, "research-assistant/tool.py")
	}
	if tool1.HarnessID != "autofix-1234567890" {
		t.Errorf("Tools[0].HarnessID = %q, want %q", tool1.HarnessID, "autofix-1234567890")
	}
	if tool1.CacheHit {
		t.Error("Tools[0].CacheHit = true, want false (ToolInput.CacheHit was not set for this input)")
	}
	if tool1.FindingsCount != 1 {
		t.Errorf("Tools[0].FindingsCount = %d, want 1", tool1.FindingsCount)
	}
	if len(tool1.Egress) != 1 || tool1.Egress[0].Host != "api.perplexity.ai" {
		t.Errorf("Tools[0].Egress = %+v, want [{Host: api.perplexity.ai}]", tool1.Egress)
	}

	tool2 := p.Tools[1]
	if tool2.HarnessID != "" {
		t.Errorf("Tools[1].HarnessID = %q, want empty (static-only)", tool2.HarnessID)
	}
	if len(tool2.Egress) != 1 || tool2.Egress[0].Host != "api.marketdata.io" {
		t.Errorf("Tools[1].Egress = %+v, want [{Host: api.marketdata.io}]", tool2.Egress)
	}

	// Cross-contamination check: tool1's egress must not include tool2's host.
	for _, ep := range tool1.Egress {
		if ep.Host == "api.marketdata.io" {
			t.Error("Tools[0].Egress leaked Tools[1]'s host — per-tool attribution broken")
		}
	}
}

// TestBuild_CacheHitPassesThrough confirms ToolInput.CacheHit (set by the
// caller when a scan reused a cached sandbox result) flows through to
// ToolProfile.CacheHit unchanged, per tool.
func TestBuild_CacheHitPassesThrough(t *testing.T) {
	inputs := []ToolInput{
		{Path: "cached-tool/tool.py", CacheHit: true},
		{Path: "fresh-tool/tool.py", CacheHit: false},
	}
	p := Build("./demo", "", inputs, nil, nil)

	if len(p.Tools) != 2 {
		t.Fatalf("len(Tools) = %d, want 2", len(p.Tools))
	}
	if !p.Tools[0].CacheHit {
		t.Error("Tools[0].CacheHit = false, want true")
	}
	if p.Tools[1].CacheHit {
		t.Error("Tools[1].CacheHit = true, want false")
	}
}

func TestBuild_EmptyInputs(t *testing.T) {
	p := Build("./demo", "", nil, nil, nil)
	if p.GrantSet != nil {
		t.Errorf("GrantSet = %+v, want nil for zero tools", p.GrantSet)
	}
	if p.Tools != nil {
		t.Errorf("Tools = %+v, want nil for zero tools", p.Tools)
	}
}

// TestBuild_DeniedHostExcludedFromEgress confirms probe.profile.json's
// per-tool egress table stays consistent with the generated policy draft —
// a denied destination never shows up as this tool's egress either.
func TestBuild_DeniedHostExcludedFromEgress(t *testing.T) {
	inputs := []ToolInput{
		{
			Path: "leaky-tool/tool.py",
			Src: `// Outbound: 169.254.169.254:80
// Outbound: api.stripe.com:443`,
		},
	}
	p := Build("./demo", "", inputs, policy.BuiltinDenyList(), nil)

	if len(p.Tools) != 1 {
		t.Fatalf("len(Tools) = %d, want 1", len(p.Tools))
	}
	for _, ep := range p.Tools[0].Egress {
		if ep.Host == "169.254.169.254" {
			t.Fatalf("denied host 169.254.169.254 appeared in Egress: %+v", p.Tools[0].Egress)
		}
	}
	if len(p.Tools[0].Egress) != 1 || p.Tools[0].Egress[0].Host != "api.stripe.com" {
		t.Errorf("Egress = %+v, want only api.stripe.com", p.Tools[0].Egress)
	}
}

// TestBuild_PlatformSourceTaggedInEgress confirms probe.profile.json's
// per-tool egress table shows source="platform" on entries matched via a
// platform allow list — the roadmap's literal done-condition for this slice.
func TestBuild_PlatformSourceTaggedInEgress(t *testing.T) {
	allow := policy.NewAllowList()
	allow.AddHost("nim.internal.example.com", policy.SourcePlatform)

	inputs := []ToolInput{
		{
			Path: "agent-tool/tool.py",
			Src:  `// Outbound: nim.internal.example.com:443`,
		},
	}
	p := Build("./demo", "billing", inputs, nil, allow)

	if len(p.Tools) != 1 || len(p.Tools[0].Egress) != 1 {
		t.Fatalf("unexpected shape: %+v", p.Tools)
	}
	if got := p.Tools[0].Egress[0].Source; got != policy.SourcePlatform {
		t.Errorf("Egress[0].Source = %q, want %q", got, policy.SourcePlatform)
	}
}

// TestBuild_NotInAllowListExcludedFromEgress confirms an observed-but-
// undeclared host doesn't appear in probe.profile.json's egress table once
// an allow list is active — stays consistent with the generated draft.
// TestBuild_GrantSetHash_DeterministicAndOrderIndependent confirms the
// grant-set hash added in the Policy-ingest-contract slice is stable
// regardless of the order tools were scanned in — a class YAML with its
// members reordered must still hash to the same value, since only the
// member set (not YAML order) should affect drift detection.
func TestBuild_GrantSetHash_DeterministicAndOrderIndependent(t *testing.T) {
	inputsA := []ToolInput{
		{Path: "research-assistant/tool.py"},
		{Path: "js-weather/tool.js"},
	}
	inputsB := []ToolInput{
		{Path: "js-weather/tool.js"},
		{Path: "research-assistant/tool.py"},
	}

	pA := Build("./demo", "disjoint-demo", inputsA, nil, nil)
	pB := Build("./demo", "disjoint-demo", inputsB, nil, nil)

	if pA.GrantSetHash == "" {
		t.Fatal("GrantSetHash is empty, want a non-empty hash for a non-empty grant set")
	}
	if pA.GrantSetHash != pB.GrantSetHash {
		t.Errorf("GrantSetHash differs by member order: %q vs %q", pA.GrantSetHash, pB.GrantSetHash)
	}
}

// TestBuild_GrantSetHash_EmptyForZeroTools confirms no hash is produced
// when there's nothing to hash, matching GrantSet's own nil-for-zero-tools
// behavior (TestBuild_EmptyInputs).
func TestBuild_GrantSetHash_EmptyForZeroTools(t *testing.T) {
	p := Build("./demo", "", nil, nil, nil)
	if p.GrantSetHash != "" {
		t.Errorf("GrantSetHash = %q, want empty for zero tools", p.GrantSetHash)
	}
}

// TestBuild_GrantSetHash_DiffersOnDifferentMemberSet confirms the hash
// actually reflects the grant set's content, not just its length — a
// changed member set (drift) must change the hash.
func TestBuild_GrantSetHash_DiffersOnDifferentMemberSet(t *testing.T) {
	inputsA := []ToolInput{{Path: "research-assistant/tool.py"}, {Path: "js-weather/tool.js"}}
	inputsB := []ToolInput{{Path: "research-assistant/tool.py"}, {Path: "go-fetcher/tool.go"}}

	pA := Build("./demo", "disjoint-demo", inputsA, nil, nil)
	pB := Build("./demo", "disjoint-demo", inputsB, nil, nil)

	if pA.GrantSetHash == pB.GrantSetHash {
		t.Errorf("GrantSetHash matched for different member sets: %q", pA.GrantSetHash)
	}
}

func TestBuild_NotInAllowListExcludedFromEgress(t *testing.T) {
	allow := policy.NewAllowList()
	allow.AddHost("api.stripe.com", policy.SourceDeclared)

	inputs := []ToolInput{
		{
			Path: "leaky-tool/tool.py",
			Src: `// Outbound: api.stripe.com:443
// Outbound: api.undeclared.com:443`,
		},
	}
	p := Build("./demo", "", inputs, nil, allow)

	if len(p.Tools) != 1 || len(p.Tools[0].Egress) != 1 || p.Tools[0].Egress[0].Host != "api.stripe.com" {
		t.Errorf("Egress = %+v, want only api.stripe.com", p.Tools[0].Egress)
	}
}
