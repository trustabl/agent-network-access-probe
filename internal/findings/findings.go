// Package findings builds probe.findings.json — the always-written,
// review-independent evidence artifact a downstream consumer (e.g.
// Trustabl Policy) can merge from disk without a human pasting anything.
// Distinct from autofix-session.json, which only exists for runs where
// interactive fix review actually happened and is shaped around
// accept/reject decisions rather than raw evidence.
package findings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/trustabl/probe/internal/profile"
	"github.com/trustabl/probe/internal/sandbox"
)

// Finding is one candidate, attributed to the file it came from where
// possible. Embeds sandbox.Candidate directly so every finding's
// title/description/severity/score_impact/evidence/fix_hint is reused
// as-is (Candidate already carries full json tags) with no duplication.
type Finding struct {
	// File is empty for a run-level finding not attributable to one file
	// (e.g. a --class union/split finding) — a class-shape concern, not a
	// per-file one.
	File string `json:"file,omitempty"`
	sandbox.Candidate
}

// Report is probe.findings.json for one Probe run.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   string    `json:"generated_at"`
	Class         string    `json:"class,omitempty"`
	Source        string    `json:"source"`
	Findings      []Finding `json:"findings"`
}

// Build assembles a Report from per-tool findings (attributed to that
// tool's file via toolInputs) plus any run-level findings not tied to one
// file (runLevel). Findings is always a non-nil, possibly empty slice —
// unlike Profile.GrantSet, this file must stay a parseable array even on a
// clean run, since a consumer reads it standalone without cross-checking
// candidate counts elsewhere first.
func Build(sourcePath, class string, toolInputs []profile.ToolInput, runLevel []sandbox.Candidate) *Report {
	r := &Report{
		SchemaVersion: "1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Class:         class,
		Source:        sourcePath,
		Findings:      []Finding{},
	}
	for _, in := range toolInputs {
		for _, c := range in.Candidates {
			r.Findings = append(r.Findings, Finding{File: in.Path, Candidate: c})
		}
	}
	for _, c := range runLevel {
		r.Findings = append(r.Findings, Finding{Candidate: c})
	}
	return r
}

// Write marshals r to indented JSON and writes it to destDir/probe.findings.json.
func Write(r *Report, destDir string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(destDir, "probe.findings.json"), data, 0o644)
}
