# Gating CI on the generated policy and findings

`autofix fix` generates a least-privilege OpenShell policy from observed
network egress, plus a session's worth of findings and a
production-readiness score. `autofix verify` checks that session's record
(the attestation) and optionally fails the build on a low score or critical
findings. Run it in your own CI, right after `autofix fix`.

## Optional: signing for a stricter gate

By default, gating on `--min-score` / `--fail-on-critical` works against an
unsigned attestation — that's enough to catch regressions in most CI setups.
For a stricter gate, `autofix fix` can also sign the attestation with
[Sigstore](https://www.sigstore.dev/) keyless signing: an ephemeral keypair
is generated, exchanged for a short-lived certificate from the public-good
Fulcio CA bound to your CI's OIDC identity, and a Rekor transparency log
entry is recorded. No private key is ever stored or managed.

The signature is what makes `--require-signature` meaningful — it asserts
"this record was produced by a run of *this* workflow, in *this* repo." An
attacker on a malicious PR can't forge a passing gate without controlling
that CI identity.

Signing is best-effort: if no OIDC credential is available (no CI, or no
`id-token: write` permission), `autofix fix` still completes and writes an
unsigned attestation with a warning on stderr. Use `--require-signature` on
`verify` to make an unsigned attestation fail the gate once you're ready to
enforce it.

## GitHub Actions example

```yaml
name: autofix-gate
on: [pull_request]

permissions:
  id-token: write   # required — Fulcio needs this OIDC token. Without it,
                     # signing silently falls back to an interactive flow
                     # that fails non-interactively in CI.
  contents: read

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download autofix
        run: |
          curl -L https://github.com/trustabl/agent-network-access-probe/releases/latest/download/autofix_linux_amd64.tar.gz | tar xz
          chmod +x autofix

      - name: Scan and attest
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: ./autofix fix --source . --entrypoint tool.py --model gpt-4o --output json --auto-accept

      - name: Verify attestation and gate
        run: |
          ./autofix verify ./autofix-attestation.json \
            --require-signature \
            --identity "https://github.com/${{ github.repository }}/.*" \
            --issuer "https://token.actions.githubusercontent.com" \
            --min-score 70 \
            --fail-on-critical
```

## `verify` flags

| Flag | Default | Description |
|---|---|---|
| `--min-score` | `0` (no gate) | Fail if `production_readiness_score` is below this value |
| `--fail-on-critical` | `false` | Fail if any critical findings are present |
| `--require-signature` | `false` | Fail if no valid Sigstore signature is present |
| `--identity` | — | Regex the signer's certificate SAN must match |
| `--issuer` | — | Regex the signer's OIDC issuer must match |
| `--output` | `text` | Output format: `text` or `json` |

Start with `--require-signature` unset while rolling this out across teams —
plain score/critical gating still works on unsigned attestations. Once every
team's CI has `id-token: write` configured, add `--require-signature` to
close the loop.