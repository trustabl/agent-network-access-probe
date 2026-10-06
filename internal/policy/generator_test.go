package policy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/trustabl/agent-network-access-probe/internal/sandbox"
)

// TestGenerate_ProtocolIsTCP is a regression test for a schema bug: Generate
// used to emit `protocol: https`/`protocol: http` (the URL scheme) instead of
// the transport protocol OpenShell's network_policies schema expects — which
// disagreed with the repo's own OpenShell-shaped fixture
// (demo/research-assistant/overly-broad-policy.yaml, which uses `protocol: tcp`
// throughout).
func TestGenerate_ProtocolIsTCP(t *testing.T) {
	srcContents := map[string]string{
		"tool.py": `import requests
requests.get("https://api.perplexity.ai/search")
`,
	}
	doc := Generate(nil, srcContents, nil, nil)

	if len(doc.NetworkPolicies.Outbound) != 1 {
		t.Fatalf("got %d outbound entries, want 1: %+v", len(doc.NetworkPolicies.Outbound), doc.NetworkPolicies.Outbound)
	}
	ep := doc.NetworkPolicies.Outbound[0]
	if ep.Host != "api.perplexity.ai" {
		t.Errorf("Host = %q, want %q", ep.Host, "api.perplexity.ai")
	}
	if ep.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want %q", ep.Protocol, "tcp")
	}
	if ep.Port != 443 {
		t.Errorf("Port = %d, want 443", ep.Port)
	}
}

// TestExtractToolEndpoints_ScopedToOneTool confirms the per-tool primitive
// only sees the candidates/source passed to it, not a whole-run's worth.
func TestExtractToolEndpoints_ScopedToOneTool(t *testing.T) {
	src := `// Outbound: internal-orders.acme.com:8443
`
	got, denied, notInAllow := ExtractToolEndpoints(nil, src, nil, nil)
	if len(denied) != 0 {
		t.Fatalf("got %d denied, want 0 (no deny list passed): %+v", len(denied), denied)
	}
	if len(notInAllow) != 0 {
		t.Fatalf("got %d notInAllow, want 0 (no allow list passed): %+v", len(notInAllow), notInAllow)
	}
	if len(got) != 1 {
		t.Fatalf("got %d endpoints, want 1: %+v", len(got), got)
	}
	if got[0].Host != "internal-orders.acme.com" || got[0].Port != 8443 || got[0].Protocol != "tcp" {
		t.Errorf("got %+v, want {Host: internal-orders.acme.com, Port: 8443, Protocol: tcp}", got[0])
	}

	// A second, unrelated tool's source must not leak into the first tool's result.
	otherSrc := `// Outbound: other-tool-host.example.com:443
`
	gotOther, _, _ := ExtractToolEndpoints(nil, otherSrc, nil, nil)
	if len(gotOther) != 1 || gotOther[0].Host != "other-tool-host.example.com" {
		t.Fatalf("got %+v, want a single endpoint for other-tool-host.example.com", gotOther)
	}
}

// TestExtractToolEndpoints_EvidenceDedup confirms evidence-derived URLs dedupe
// with source-literal URLs for the same host+protocol.
func TestExtractToolEndpoints_EvidenceDedup(t *testing.T) {
	src := `https://api.stripe.com/v1/charges`
	candidates := []sandbox.Candidate{
		{
			Title: "Unauthorized network calls",
			Evidence: []sandbox.Evidence{
				{RawLine: "connect to https://api.stripe.com/v1/charges blocked"},
			},
		},
	}
	got, _, _ := ExtractToolEndpoints(candidates, src, nil, nil)
	if len(got) != 1 {
		t.Fatalf("got %d endpoints, want 1 (deduped): %+v", len(got), got)
	}
}

func TestGenerate_UnionsAcrossFiles(t *testing.T) {
	srcContents := map[string]string{
		"tool-a.py": `// Outbound: api.stripe.com:443`,
		"tool-b.py": `// Outbound: api.twilio.com:443`,
	}
	doc := Generate(nil, srcContents, nil, nil)
	if len(doc.NetworkPolicies.Outbound) != 2 {
		t.Fatalf("got %d outbound entries, want 2 (union across files): %+v", len(doc.NetworkPolicies.Outbound), doc.NetworkPolicies.Outbound)
	}
}

// TestExtractToolEndpoints_DeniedHostExcluded confirms a host matching the
// deny list never lands in allowed, and shows up in denied instead.
func TestExtractToolEndpoints_DeniedHostExcluded(t *testing.T) {
	src := `// Outbound: 169.254.169.254:80
// Outbound: api.perplexity.ai:443`
	got, denied, _ := ExtractToolEndpoints(nil, src, BuiltinDenyList(), nil)

	if len(got) != 1 || got[0].Host != "api.perplexity.ai" {
		t.Errorf("allowed = %+v, want only api.perplexity.ai", got)
	}
	if len(denied) != 1 || denied[0].Host != "169.254.169.254" {
		t.Errorf("denied = %+v, want only 169.254.169.254", denied)
	}
}

func TestGenerate_ExcludesDeniedFromDraft(t *testing.T) {
	srcContents := map[string]string{
		"tool.py": `// Outbound: 169.254.169.254:80
// Outbound: api.stripe.com:443`,
	}
	doc := Generate(nil, srcContents, BuiltinDenyList(), nil)
	for _, ep := range doc.NetworkPolicies.Outbound {
		if ep.Host == "169.254.169.254" {
			t.Fatalf("denied host 169.254.169.254 appeared in the generated draft: %+v", doc.NetworkPolicies.Outbound)
		}
	}
	if len(doc.NetworkPolicies.Outbound) != 1 || doc.NetworkPolicies.Outbound[0].Host != "api.stripe.com" {
		t.Errorf("Outbound = %+v, want only api.stripe.com", doc.NetworkPolicies.Outbound)
	}
}

// TestExtractToolEndpoints_NotOnAllowListExcluded confirms that once an
// allow list is supplied, an observed-but-undeclared host is excluded from
// allowed and reported in notInAllow instead — "do not auto-add".
func TestExtractToolEndpoints_NotOnAllowListExcluded(t *testing.T) {
	allow := NewAllowList()
	allow.AddHost("api.perplexity.ai", SourceDeclared)

	src := `// Outbound: api.perplexity.ai:443
// Outbound: api.undeclared.com:443`
	got, _, notInAllow := ExtractToolEndpoints(nil, src, nil, allow)

	if len(got) != 1 || got[0].Host != "api.perplexity.ai" {
		t.Errorf("allowed = %+v, want only api.perplexity.ai", got)
	}
	if got[0].Source != SourceDeclared {
		t.Errorf("allowed[0].Source = %q, want %q", got[0].Source, SourceDeclared)
	}
	if len(notInAllow) != 1 || notInAllow[0].Host != "api.undeclared.com" {
		t.Errorf("notInAllow = %+v, want only api.undeclared.com", notInAllow)
	}
}

// TestExtractToolEndpoints_PlatformSourceTagged confirms a host matched via
// a platform allow entry is tagged Source: "platform" — the roadmap's
// literal done-condition for this slice.
func TestExtractToolEndpoints_PlatformSourceTagged(t *testing.T) {
	allow := NewAllowList()
	allow.AddHost("nim.internal.example.com", SourcePlatform)

	src := `// Outbound: nim.internal.example.com:443`
	got, _, _ := ExtractToolEndpoints(nil, src, nil, allow)

	if len(got) != 1 {
		t.Fatalf("got %d endpoints, want 1: %+v", len(got), got)
	}
	if got[0].Source != SourcePlatform {
		t.Errorf("Source = %q, want %q", got[0].Source, SourcePlatform)
	}
}

// TestExtractToolEndpoints_NoAllowListMeansUnchangedBehavior is a regression
// test: when allow is nil, every non-denied observed host is still
// automatically allowed with an empty Source, exactly like before Slice 6.
func TestExtractToolEndpoints_NoAllowListMeansUnchangedBehavior(t *testing.T) {
	src := `// Outbound: anything-goes.example.com:443`
	got, _, notInAllow := ExtractToolEndpoints(nil, src, nil, nil)

	if len(notInAllow) != 0 {
		t.Fatalf("notInAllow = %+v, want empty when allow is nil", notInAllow)
	}
	if len(got) != 1 || got[0].Host != "anything-goes.example.com" {
		t.Fatalf("allowed = %+v, want anything-goes.example.com", got)
	}
	if got[0].Source != "" {
		t.Errorf("Source = %q, want empty when allow is nil", got[0].Source)
	}
}

func TestGenerate_ExcludesNotInAllowListFromDraft(t *testing.T) {
	allow := NewAllowList()
	allow.AddHost("api.stripe.com", SourceDeclared)

	srcContents := map[string]string{
		"tool.py": `// Outbound: api.stripe.com:443
// Outbound: api.undeclared.com:443`,
	}
	doc := Generate(nil, srcContents, nil, allow)
	if len(doc.NetworkPolicies.Outbound) != 1 || doc.NetworkPolicies.Outbound[0].Host != "api.stripe.com" {
		t.Errorf("Outbound = %+v, want only api.stripe.com", doc.NetworkPolicies.Outbound)
	}
}

// TestGenerate_SourceNeverSerializedIntoDraftYAML confirms AllowedEndpoint's
// Source field is tagged yaml:"-" — network_policies.draft.yaml must stay
// exactly what OpenShell consumes, no Trustabl-only fields.
func TestGenerate_SourceNeverSerializedIntoDraftYAML(t *testing.T) {
	allow := NewAllowList()
	allow.AddHost("api.stripe.com", SourcePlatform)
	srcContents := map[string]string{"tool.py": `// Outbound: api.stripe.com:443`}
	doc := Generate(nil, srcContents, nil, allow)

	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "source") {
		t.Errorf("marshaled YAML must not contain a source field: %s", data)
	}
}
