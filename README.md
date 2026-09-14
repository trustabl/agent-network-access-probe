# Probe

> Public product: **Trustabl Probe**

Runs your agent tool in an isolated OpenShell sandbox, observes the network destinations it actually reaches, and generates a least-privilege OpenShell `network_policies` draft from that evidence — no hand-written allow list required. Static analysis also flags hardcoded credentials, missing timeouts, and other reliability issues, with AI-generated fixes for each, reviewed one by one. Your source code never leaves your environment.

> **Language support:** Static analysis is supported for Python, Go, JavaScript/TypeScript, Ruby, and Shell. Sandbox execution is available for all languages.

## How It Works

1. Your tool is uploaded to a sandboxed OpenShell environment and executed
2. Runtime evidence is collected — network destinations reached, denials, crashes, warnings, policy violations
3. Static analysis scans your source for hardcoded credentials, unauthorized network calls, missing timeouts, and more
4. You get back a least-privilege OpenShell policy YAML (unsigned draft) built from what the tool actually reached, findings from both passes, and a fixed version of the code for each issue found

Each session can also be attested: an optional signed manifest of the run, using [Sigstore](https://www.sigstore.dev/) keyless signing — no private key to manage. In CI (e.g. GitHub Actions with `permissions: id-token: write`), it signs with your workflow's identity automatically. Run locally without that, and it falls back to an interactive browser login bound to your personal identity, recorded in Sigstore's public transparency log — pass `--no-sign` to skip signing entirely instead.

Cloud metadata endpoints and link-local addresses (`169.254.169.254`, `metadata.google.internal`, `169.254.0.0/16`, `fe80::/10`) are always excluded from the generated policy, regardless of what the tool actually reaches — pass `--deny-list FILE` to add your own hosts/IPs/CIDRs on top of that built-in set.

By default, everything a tool observably reaches (and isn't denied) goes into the draft. Pass `--allow-list FILE` to make that stricter: once supplied, an observed destination not on the list is flagged instead of auto-added — the allow list becomes the required source of truth, not just an addition to what was seen. `--platform-allow-list FILE` works the same way for platform must-reach endpoints (e.g. NIM, IdP) and tags matching entries `source=platform` in `probe.profile.json`.

If a tool's code contains a call shape with a real-world side effect — a network write, a subprocess call, a filesystem delete, destructive SQL — its sandbox execution is skipped by default (static analysis still runs and still reports on it) so a default run can never actually charge, delete, or modify anything. Pass `--allow-write-tools` to run it for real once you're ready, ideally alongside `--env-fixtures FILE` so the tool picks up staging/test-mode credentials instead of production ones.

Sandbox results are cached per tool under `os.UserCacheDir()/trustabl-probe/results` — keyed by the tool's source content and effective run config (base image, `--sandbox-args`, `--env-fixtures` content), not its filesystem path, so the same tool referenced by two different agent classes reuses one cache entry. `probe.profile.json`'s `cache_hit` field reflects whether each tool's result came from the cache. Pass `--no-cache` to skip the cache entirely (neither read nor write) — always do this for release gates.

## Requirements

- A sandbox runner for `--sandbox` execution — pick one with `--runner`:
  - `docker` (default-friendly, no separate install beyond Docker itself) — [Docker Desktop or Docker Engine](https://docs.docker.com/get-docker/), daemon running. No OpenShell required.
  - `openshell` (default `--runner`) — [OpenShell](https://build.nvidia.com/openshell) installed, with `openshell gateway start` running. Also requires Python 3.8+ on the host machine, for dependency wheel downloads.
- Access to an OpenAI-compatible LLM endpoint (OpenAI, Anthropic, Ollama, LiteLLM, LM Studio, etc.)

## Setup

### 1. Install a sandbox runner

**Docker only (no OpenShell needed):** install [Docker Desktop or Docker Engine](https://docs.docker.com/get-docker/) and make sure the daemon is running (`docker info`). Pass `--runner docker` to `fix`/`watch` — that's the whole setup.

**OpenShell:**

Download from [build.nvidia.com/openshell](https://build.nvidia.com/openshell), then:

```bash
openshell gateway start   # keep running in a separate terminal
openshell sandbox list    # verify CLI is on PATH
```

### 2. Configure an LLM

**Local (Ollama):**
```bash
brew install ollama       # macOS
ollama serve
ollama pull qwen2.5-coder:32b
```

**Cloud:** set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` — the endpoint is auto-detected from the model name.

### 3. Install autofix

**macOS (Homebrew):**
```bash
brew tap trustabl/autofix
brew install autofix
```

**Windows (Scoop):**
```powershell
scoop bucket add trustabl https://github.com/trustabl/scoop-autofix
scoop install autofix
```

**Linux / manual:**
```bash
# Replace v0.1.0 with the latest version from https://github.com/trustabl/probe/releases
curl -L https://github.com/trustabl/probe/releases/download/v0.1.0/autofix_0.1.0_linux_amd64.tar.gz | tar xz
sudo mv autofix /usr/local/bin/
autofix version
```

---

## Commands

### `fix` — Generate a least-privilege policy from observed egress, and fix what's found

```bash
autofix fix --source ./my-tool
autofix fix --source ./my-tool --entrypoint tool.py --sandbox --model gpt-4o
autofix fix --source ./my-tool --existing-policy ./policy.yaml --model claude-3-5-sonnet-20241022
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--source` | required | Path to the tool directory |
| `--entrypoint` | auto-detected | Entry point script(s) — can repeat for multi-file scanning |
| `--model` | required | Model name. Cloud: `gpt-4o`, `claude-3-5-sonnet-20241022`. Local: `qwen2.5-coder:32b` (recommended) |
| `--llm-url` | auto-detected | OpenAI-compatible base URL. Auto-detected for `gpt-*` and `claude-*`. Required for all other models. |
| `--api-key` | env var | API key — defaults to `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `LLM_API_KEY` |
| `--llm-timeout` | `5m` | Per-request LLM timeout (increase for slow local models) |
| `--sandbox` | off | Run the tool in a sandbox for runtime findings |
| `--runner` | `openshell` | Sandbox runner: `openshell` or `docker` |
| `--base-image` | auto | Sandbox base image (default: auto-detected from entrypoint extension) |
| `--sandbox-args` | — | Arguments passed to the tool inside the sandbox. Value is a raw shell token — avoid shell metacharacters. |
| `--existing-policy` | — | Path to an existing OpenShell policy YAML to diff against the generated least-privilege policy |
| `--deny-list` | — | Path to a deny list file (one host/IP/CIDR per line, `#` comments) — evaluated on top of the built-in metadata/link-local deny |
| `--allow-list` | — | Path to a declared allow list file (one host/CIDR/`*.suffix` per line, `#` comments) — an observed destination not on this list is flagged, not auto-added to the draft |
| `--platform-allow-list` | — | Path to a platform allow list file (jail must-reach endpoints, e.g. NIM/IdP) — same format as `--allow-list`, tagged `source=platform` in `probe.profile.json` |
| `--allow-write-tools` | off | Allow sandbox execution of tools that appear to perform mutating/irreversible operations (default: skipped, static analysis only) |
| `--env-fixtures` | — | Path to a dotenv-style file (`KEY=value` per line, `#` comments) injected into the sandbox environment — lets a tool pick up staging credentials/endpoints instead of production ones |
| `--no-cache` | off | Skip the per-tool result cache entirely — neither read nor write it (use for release gates that must always execute for real) |
| `--auto-accept` | off | Accept all fixes without interactive review (useful for CI) |
| `--no-sign` | off | Skip Sigstore signing — no network call, no interactive browser flow, no public transparency log entry |
| `--output` | `text` | Output format: `text` or `json` |

**Output files** (written to `--source` directory):

| File | Description |
|---|---|
| `network_policies.draft.yaml` | Least-privilege OpenShell network policy (unsigned draft, built from observed egress) |
| `probe.profile.json` | Per-tool egress table, grant-set hash, and scan metadata (unsigned) |
| `probe.findings.json` | Every finding (title, severity, evidence, fix hint) with file attribution — always written, independent of whether interactive fix review ran |
| `autofix-attestation.json` | Optional signed behavioral manifest with source hash |
| `autofix-session.json` | Full session log (findings, diffs, accept/reject decisions) |
| `autofix-session.patch` | Unified diff of all accepted fixes |

---

### `watch` — Continuous improvement loop

Polls source files for changes. On every save, re-runs static analysis, rewrites `network_policies.draft.yaml`, `probe.profile.json`, `probe.findings.json`, and `autofix-attestation.json`, and prints a delta (score change, resolved/new findings, new source hash).

```bash
autofix watch --source ./my-tool
autofix watch --source ./my-tool --entrypoint tool.py --interval 1s
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--source` | required | Path to the tool directory |
| `--entrypoint` | auto-detected | Entry point script(s) to watch |
| `--interval` | `2s` | Poll interval |
| `--no-sign` | off | Skip Sigstore signing — no network call, no interactive browser flow, no public transparency log entry |
| `--deny-list` | — | Path to a deny list file (one host/IP/CIDR per line, `#` comments) — evaluated on top of the built-in metadata/link-local deny |
| `--allow-list` | — | Path to a declared allow list file (one host/CIDR/`*.suffix` per line, `#` comments) — an observed destination not on this list is flagged, not auto-added to the draft |
| `--platform-allow-list` | — | Path to a platform allow list file (jail must-reach endpoints, e.g. NIM/IdP) — same format as `--allow-list`, tagged `source=platform` in `probe.profile.json` |

---

### `verify` — Verify an attestation and gate CI

Checks an attestation's content digest and Sigstore signature, then optionally fails (non-zero exit code) on a low score or critical findings. See [docs/ci-gate.md](docs/ci-gate.md) for a full CI setup.

```bash
autofix verify ./autofix-attestation.json --min-score 70 --fail-on-critical
autofix verify ./autofix-attestation.json --require-signature --identity "https://github.com/acme-corp/.*"
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--min-score` | `0` (no gate) | Fail if `production_readiness_score` is below this value |
| `--fail-on-critical` | off | Fail if any critical findings are present |
| `--require-signature` | off | Fail if no valid Sigstore signature is present |
| `--identity` | — | Regex the signer's certificate SAN must match |
| `--issuer` | — | Regex the signer's OIDC issuer must match |
| `--output` | `text` | Output format: `text` or `json` |

---

### `version` — Print version

```bash
autofix version
```

### `license` — Print license and copyright information

```bash
autofix license
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE), or run `autofix license` to
read it in the terminal.

