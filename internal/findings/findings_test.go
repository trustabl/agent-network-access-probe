package findings

import (
	"testing"

	"github.com/trustabl/agent-network-access-probe/internal/profile"
	"github.com/trustabl/agent-network-access-probe/internal/sandbox"
)

// TestBuild_PerFileAttribution confirms each tool's own candidates are
// attributed to that tool's file path in the resulting findings list.
func TestBuild_PerFileAttribution(t *testing.T) {
	toolInputs := []profile.ToolInput{
		{
			Path: "research-assistant/tool.py",
			Candidates: []sandbox.Candidate{
				{Title: "Unbounded tool output", Severity: "warning"},
			},
		},
		{
			Path: "js-weather/tool.js",
			Candidates: []sandbox.Candidate{
				{Title: "Missing dependency declarations", Severity: "warning"},
			},
		},
	}

	r := Build("./demo", "disjoint-demo", toolInputs, nil)

	if len(r.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2: %+v", len(r.Findings), r.Findings)
	}
	if r.Findings[0].File != "research-assistant/tool.py" || r.Findings[0].Title != "Unbounded tool output" {
		t.Errorf("Findings[0] = %+v, want file=research-assistant/tool.py title=Unbounded tool output", r.Findings[0])
	}
	if r.Findings[1].File != "js-weather/tool.js" || r.Findings[1].Title != "Missing dependency declarations" {
		t.Errorf("Findings[1] = %+v, want file=js-weather/tool.js title=Missing dependency declarations", r.Findings[1])
	}
}

// TestBuild_RunLevelFindingHasNoFile confirms a run-level finding (e.g. the
// class-split finding) is included with an empty File, distinguishing it
// from a per-file finding rather than misattributing it to some tool.
func TestBuild_RunLevelFindingHasNoFile(t *testing.T) {
	runLevel := []sandbox.Candidate{
		{Title: "Class union grants some tools network access they don't individually need", Severity: "warning"},
	}

	r := Build("./demo", "disjoint-demo", nil, runLevel)

	if len(r.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(r.Findings))
	}
	if r.Findings[0].File != "" {
		t.Errorf("Findings[0].File = %q, want empty for a run-level finding", r.Findings[0].File)
	}
	if r.Findings[0].Title != "Class union grants some tools network access they don't individually need" {
		t.Errorf("Findings[0].Title = %q, unexpected", r.Findings[0].Title)
	}
}

// TestBuild_EmptyFindingsIsNonNil confirms probe.findings.json stays a
// parseable array ("findings": []) on a clean run, since a consumer reads
// this file standalone without cross-checking candidate counts elsewhere.
func TestBuild_EmptyFindingsIsNonNil(t *testing.T) {
	r := Build("./demo", "", nil, nil)
	if r.Findings == nil {
		t.Fatal("Findings is nil, want a non-nil empty slice")
	}
	if len(r.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(r.Findings))
	}
}
