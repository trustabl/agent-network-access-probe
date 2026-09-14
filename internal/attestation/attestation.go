package attestation

import (
	"context"
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

// Manifest is the behavioral attestation document written to autofix-attestation.json.
// SHA256 is a content digest of the manifest with SHA256 and SigstoreBundle set to
// their zero values. SigstoreBundle carries real cryptographic provenance (Fulcio
// cert + Rekor log entry) when signing succeeds; signing is best-effort, so it may
// be absent (e.g. no CI OIDC credential, offline dev environment).
type Manifest struct {
	SchemaVersion            string                   `json:"schema_version"`
	GeneratedAt              string                   `json:"generated_at"`
	Source                   string                   `json:"source"`
	Entrypoints              []string                 `json:"entrypoints"`
	LanguagesDetected        []string                 `json:"languages_detected"`
	NetworkCalls             []policy.AllowedEndpoint `json:"network_calls"`
	FileAccessPatterns       FileAccessPatterns       `json:"file_access_patterns"`
	FindingsSummary          FindingsSummary          `json:"findings_summary"`
	ProductionReadinessScore int                      `json:"production_readiness_score"`
	SourceHash               string                   `json:"source_hash,omitempty"`
	SigstoreBundle           *SigstoreBundle           `json:"sigstore_bundle,omitempty"`
	SHA256                   string                   `json:"sha256"`
}

// FileAccessPatterns describes the filesystem access the tool requires.
type FileAccessPatterns struct {
	ReadOnly  []string `json:"read_only"`
	ReadWrite []string `json:"read_write"`
}

// FindingsSummary is a count of findings by severity.
type FindingsSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
}

// Build assembles the attestation manifest from scan inputs.
// Network calls are read from policyDoc to avoid redundant URL extraction.
func Build(
	candidates []sandbox.Candidate,
	entrypoints []string,
	sourcePath string,
	policyDoc *policy.PolicyDoc,
) *Manifest {
	m := &Manifest{
		SchemaVersion: "1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Source:        sourcePath,
		Entrypoints:   entrypoints,
	}

	// Languages from entrypoint extensions.
	langSeen := map[string]bool{}
	for _, ep := range entrypoints {
		if lang := ExtToLanguage(filepath.Ext(ep)); lang != "" && !langSeen[lang] {
			langSeen[lang] = true
			m.LanguagesDetected = append(m.LanguagesDetected, lang)
		}
	}

	// Network calls from already-generated policy.
	m.NetworkCalls = policyDoc.NetworkPolicies.Outbound
	if m.NetworkCalls == nil {
		m.NetworkCalls = []policy.AllowedEndpoint{}
	}

	// Filesystem access from policy.
	m.FileAccessPatterns = FileAccessPatterns{
		ReadOnly:  policyDoc.FilesystemPolicy.ReadOnly,
		ReadWrite: policyDoc.FilesystemPolicy.ReadWrite,
	}

	// Findings summary + production readiness score.
	score := 100
	for _, c := range candidates {
		m.FindingsSummary.Total++
		score += c.ScoreImpact
		switch c.Severity {
		case "critical":
			m.FindingsSummary.Critical++
		case "warning":
			m.FindingsSummary.Warning++
		default:
			m.FindingsSummary.Info++
		}
	}
	if score < 0 {
		score = 0
	}
	m.ProductionReadinessScore = score

	// Hash entrypoint source files — provides a behavioral fingerprint.
	// Sort for determinism; include filename so renames are detected.
	h := sha256.New()
	sortedEps := append([]string{}, entrypoints...)
	sort.Strings(sortedEps)
	for _, ep := range sortedEps {
		data, err := os.ReadFile(filepath.Join(sourcePath, ep))
		if err != nil {
			continue
		}
		h.Write([]byte(ep))
		h.Write(data)
	}
	m.SourceHash = fmt.Sprintf("%x", h.Sum(nil))

	return m
}

// Sign computes a SHA256 content digest of the manifest (with SHA256 and
// SigstoreBundle set to their zero values), populates the SHA256 field, then
// attempts Sigstore keyless signing over that same content and populates
// SigstoreBundle if it succeeds. Signing is best-effort: a missing OIDC
// credential or unreachable Fulcio/Rekor only produces a stderr warning —
// the attestation is still written, just unsigned, so `fix` keeps working in
// every environment. If skipSign is true, Sigstore signing is skipped
// entirely — no network call, no interactive OIDC browser flow — useful for
// local/offline runs where you don't want a browser popping up or your email
// recorded in Sigstore's public transparency log. Returns the final indented
// JSON bytes.
func Sign(m *Manifest, skipSign bool) ([]byte, error) {
	m.SHA256 = ""
	m.SigstoreBundle = nil
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	m.SHA256 = fmt.Sprintf("%x", digest)

	if skipSign {
		return json.MarshalIndent(m, "", "  ")
	}

	signedPayload, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if b, signErr := SignKeyless(ctx, signedPayload); signErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not sign attestation with Sigstore (%v) — attestation will be written unsigned\n", signErr)
	} else {
		m.SigstoreBundle = b
	}

	return json.MarshalIndent(m, "", "  ")
}

// Write signs the manifest and writes it to destDir/autofix-attestation.json.
// See Sign for the meaning of skipSign.
func Write(m *Manifest, destDir string, skipSign bool) error {
	data, err := Sign(m, skipSign)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(destDir, "autofix-attestation.json"), data, 0o644)
}

// ExtToLanguage maps a file extension to its detected language name.
func ExtToLanguage(ext string) string {
	switch ext {
	case ".py":
		return "python"
	case ".go":
		return "go"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".rb":
		return "ruby"
	case ".sh":
		return "shell"
	default:
		return ""
	}
}
