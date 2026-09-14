package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trustabl/probe/internal/attestation"
)

type verifyResult struct {
	Verified      bool   `json:"verified"`
	SHA256OK      bool   `json:"sha256_ok"`
	SignatureOK   bool   `json:"signature_ok"`
	SignaturePresent bool `json:"signature_present"`
	Score         int    `json:"score"`
	Critical      int    `json:"critical"`
	Error         string `json:"error,omitempty"`
}

var (
	verifyMinScore         int
	verifyFailOnCritical   bool
	verifyRequireSignature bool
	verifyIdentity         string
	verifyIssuer           string
	verifyOutputFmt        string
)

var verifyCmd = &cobra.Command{
	Use:   "verify <attestation.json>",
	Short: "Verify a signed attestation and gate CI on score/findings",
	Long: `Verify a behavioral attestation's content digest and Sigstore signature,
then optionally gate on production readiness score and critical findings.

Designed for CI: a failed check returns a non-zero exit code.

  autofix fix --source . --entrypoint tool.py --model gpt-4o --output json --auto-accept
  autofix verify ./autofix-attestation.json \
    --require-signature \
    --identity "https://github.com/acme-corp/.*" \
    --min-score 70 \
    --fail-on-critical`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := runVerify(args[0])
		if verifyOutputFmt == "json" {
			result.Error = errString(err)
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(result)
		}
		return err
	},
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func runVerify(path string) (verifyResult, error) {
	var result verifyResult

	data, err := os.ReadFile(path)
	if err != nil {
		return result, fmt.Errorf("read attestation: %w", err)
	}
	var m attestation.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return result, fmt.Errorf("parse attestation: %w", err)
	}
	result.Score = m.ProductionReadinessScore
	result.Critical = m.FindingsSummary.Critical
	result.SignaturePresent = m.SigstoreBundle != nil

	// 1. Content-digest check — recompute SHA256 over the manifest with
	// SHA256 and SigstoreBundle zeroed, exactly as attestation.Sign() did.
	claimedSHA256 := m.SHA256
	claimedBundle := m.SigstoreBundle
	digestCheck := m
	digestCheck.SHA256 = ""
	digestCheck.SigstoreBundle = nil
	raw, err := json.MarshalIndent(&digestCheck, "", "  ")
	if err != nil {
		return result, fmt.Errorf("re-marshal for digest check: %w", err)
	}
	digest := sha256.Sum256(raw)
	actualSHA256 := fmt.Sprintf("%x", digest)
	if actualSHA256 != claimedSHA256 {
		return result, fmt.Errorf("attestation tampered: sha256 mismatch (claimed %s, computed %s)", claimedSHA256, actualSHA256)
	}
	result.SHA256OK = true
	fmt.Fprintf(os.Stderr, "%s  content digest verified (sha256 matches)\n", styleAccept.Render("✓"))

	// 2. Sigstore signature check.
	if verifyRequireSignature || claimedBundle != nil {
		signedPayloadCheck := m
		signedPayloadCheck.SigstoreBundle = nil // SHA256 stays populated — that's what was actually signed
		signedPayload, err := json.MarshalIndent(&signedPayloadCheck, "", "  ")
		if err != nil {
			return result, fmt.Errorf("re-marshal for signature check: %w", err)
		}
		if _, err := attestation.VerifyKeyless(signedPayload, claimedBundle, verifyIdentity, verifyIssuer); err != nil {
			return result, fmt.Errorf("signature verification failed: %w", err)
		}
		result.SignatureOK = true
		fmt.Fprintf(os.Stderr, "%s  sigstore signature verified\n", styleAccept.Render("✓"))
	} else {
		fmt.Fprintf(os.Stderr, "%s  no sigstore signature present (not required)\n", stylePrompt.Render("⚠"))
	}

	// 3. CI gates.
	if verifyMinScore > 0 && m.ProductionReadinessScore < verifyMinScore {
		return result, fmt.Errorf("score %d is below minimum %d", m.ProductionReadinessScore, verifyMinScore)
	}
	if verifyFailOnCritical && m.FindingsSummary.Critical > 0 {
		return result, fmt.Errorf("%d critical finding(s) present", m.FindingsSummary.Critical)
	}

	result.Verified = true
	fmt.Fprintf(os.Stderr, "%s  all checks passed\n", styleAccept.Render("✓"))
	return result, nil
}

func init() {
	verifyCmd.Flags().IntVar(&verifyMinScore, "min-score", 0, "Fail if production_readiness_score is below this value (0 = no gate)")
	verifyCmd.Flags().BoolVar(&verifyFailOnCritical, "fail-on-critical", false, "Fail if any critical findings are present")
	verifyCmd.Flags().BoolVar(&verifyRequireSignature, "require-signature", false, "Fail if no valid Sigstore signature is present")
	verifyCmd.Flags().StringVar(&verifyIdentity, "identity", "", "Regex the signer's Fulcio certificate SAN must match (e.g. a GitHub Actions workflow ref)")
	verifyCmd.Flags().StringVar(&verifyIssuer, "issuer", "", "Regex the signer's OIDC issuer must match (e.g. https://token.actions.githubusercontent.com)")
	verifyCmd.Flags().StringVar(&verifyOutputFmt, "output", "text", "Output format: text or json")
}
