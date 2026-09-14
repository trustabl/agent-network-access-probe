package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

// SigstoreBundle wraps a Sigstore signing bundle (ephemeral-key signature +
// short-lived Fulcio certificate + Rekor transparency log entry) attached to
// a signed attestation. Stored as opaque JSON so Manifest doesn't need to
// depend on sigstore-go's protobuf bundle type directly.
type SigstoreBundle struct {
	MediaType string          `json:"mediaType"`
	Bundle    json.RawMessage `json:"bundle"`
}

const (
	githubRequestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	githubRequestURLEnv   = "ACTIONS_ID_TOKEN_REQUEST_URL"
)

// SignKeyless signs payload using Sigstore keyless signing: an ephemeral
// keypair is generated, exchanged for a short-lived Fulcio certificate bound
// to the caller's OIDC identity, and a Rekor transparency log entry is
// recorded against the public-good Sigstore instance. The OIDC identity
// comes from the ambient GitHub Actions credential when present (requires
// `permissions: id-token: write` in the workflow), or falls back to an
// interactive browser-based OAuth flow for local/manual use.
func SignKeyless(ctx context.Context, payload []byte) (*SigstoreBundle, error) {
	idToken, err := ambientOIDCToken(ctx)
	if err != nil {
		return nil, err
	}

	tufClient, err := tuf.New(tuf.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("init TUF client: %w", err)
	}
	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return nil, fmt.Errorf("fetch trusted root: %w", err)
	}
	signingConfig, err := root.GetSigningConfig(tufClient)
	if err != nil {
		return nil, fmt.Errorf("fetch signing config: %w", err)
	}

	fulcioService, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), sign.FulcioAPIVersions, time.Now())
	if err != nil {
		return nil, fmt.Errorf("select fulcio service: %w", err)
	}
	rekorServices, err := root.SelectServices(
		signingConfig.RekorLogURLs(),
		signingConfig.RekorLogURLsConfig(),
		sign.RekorAPIVersions,
		time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("select rekor service: %w", err)
	}

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral keypair: %w", err)
	}

	opts := sign.BundleOptions{
		TrustedRoot: trustedRoot,
		CertificateProvider: sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: fulcioService.URL,
			Timeout: 30 * time.Second,
			Retries: 1,
		}),
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: idToken},
	}
	for _, rekorService := range rekorServices {
		opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(&sign.RekorOptions{
			BaseURL: rekorService.URL,
			Timeout: 90 * time.Second,
			Retries: 1,
			Version: rekorService.MajorAPIVersion,
		}))
	}

	protoBundle, err := sign.Bundle(&sign.PlainData{Data: payload}, keypair, opts)
	if err != nil {
		return nil, fmt.Errorf("sign bundle: %w", err)
	}
	bundleJSON, err := protojson.Marshal(protoBundle)
	if err != nil {
		return nil, fmt.Errorf("marshal bundle: %w", err)
	}
	return &SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
		Bundle:    bundleJSON,
	}, nil
}

// VerifyKeyless checks a SigstoreBundle against the public-good Rekor log and
// Fulcio trust root: it confirms payload matches the digest the bundle
// actually signed, and that there is a valid certificate chain plus
// transparency log inclusion proof. If identityPattern and/or issuerPattern
// are non-empty, the signer's Fulcio certificate SAN/issuer must also match
// those regular expressions — this is what makes the check meaningful for a
// CI gate (e.g. "issuer must be GitHub Actions, SAN must be this repo's
// workflow"). Passing both as "" still requires a structurally valid,
// transparency-logged signature, just without pinning who signed it.
func VerifyKeyless(payload []byte, b *SigstoreBundle, identityPattern, issuerPattern string) (*verify.VerificationResult, error) {
	if b == nil {
		return nil, errors.New("no sigstore bundle present on this attestation")
	}

	parsedBundle := new(bundle.Bundle)
	if err := json.Unmarshal(b.Bundle, parsedBundle); err != nil {
		return nil, fmt.Errorf("parse sigstore bundle: %w", err)
	}

	tufClient, err := tuf.New(tuf.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("init TUF client: %w", err)
	}
	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return nil, fmt.Errorf("fetch trusted root: %w", err)
	}

	sev, err := verify.NewVerifier(
		root.TrustedMaterialCollection{trustedRoot},
		verify.WithSignedCertificateTimestamps(1),
		verify.WithObserverTimestamps(1),
		verify.WithTransparencyLog(1),
	)
	if err != nil {
		return nil, fmt.Errorf("init verifier: %w", err)
	}

	digest := sha256.Sum256(payload)
	artifactPolicy := verify.WithArtifactDigest("sha256", digest[:])

	var identityPolicies []verify.PolicyOption
	if identityPattern != "" || issuerPattern != "" {
		certID, err := verify.NewShortCertificateIdentity("", issuerPattern, "", identityPattern)
		if err != nil {
			return nil, fmt.Errorf("build identity policy: %w", err)
		}
		identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(certID))
	}

	res, err := sev.Verify(parsedBundle, verify.NewPolicy(artifactPolicy, identityPolicies...))
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}
	return res, nil
}

// ambientOIDCToken returns a Fulcio-compatible OIDC ID token. It first tries
// the GitHub Actions ambient credential (present when the workflow has
// `permissions: id-token: write`); if that's unavailable, it falls back to
// Sigstore's public interactive browser OAuth flow, matching what `cosign
// sign-blob` does for local/manual use.
func ambientOIDCToken(ctx context.Context) (string, error) {
	if tok, err := githubActionsOIDCToken(ctx); err == nil {
		return tok, nil
	}
	idToken, err := oauthflow.OIDConnect(
		"https://oauth2.sigstore.dev/auth",
		"sigstore",
		"",
		"",
		oauthflow.DefaultIDTokenGetter,
	)
	if err != nil {
		return "", fmt.Errorf("no ambient CI credential found and interactive OIDC flow failed: %w", err)
	}
	return idToken.RawString, nil
}

// githubActionsOIDCToken fetches a Sigstore-audience OIDC token using the
// ambient GitHub Actions credential exposed via ACTIONS_ID_TOKEN_REQUEST_URL/
// ACTIONS_ID_TOKEN_REQUEST_TOKEN. See
// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
func githubActionsOIDCToken(ctx context.Context) (string, error) {
	reqURL := os.Getenv(githubRequestURLEnv)
	reqToken := os.Getenv(githubRequestTokenEnv)
	if reqURL == "" || reqToken == "" {
		return "", errors.New("not running in GitHub Actions with id-token: write permission")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL+"&audience=sigstore", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+reqToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("github OIDC token request failed: %s: %s", resp.Status, string(body))
	}
	var payload struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.Value == "" {
		return "", errors.New("github OIDC token response had empty value")
	}
	return payload.Value, nil
}
