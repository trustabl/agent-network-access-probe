---
name: probe-scan
description: >-
  Use when the user wants to check an AI agent tool before shipping it: what it
  can reach on the network, a least-privilege network allow list, or runtime
  problems (crashes, missing dependencies, blocked connections). Runs Trustabl
  Probe on the tool's directory and applies the fix hints it returns.
---

# Check an agent tool with Trustabl Probe

Probe reads a directory of agent tool code (Python, Go, JavaScript/TypeScript,
Ruby, Shell) and flags problems such as missing timeouts, hardcoded credentials or
unfiltered tool output. It drafts the network allow list the tool needs (an
OpenShell network policy). With a sandbox it also runs the tool with its network
blocked, which catches problems that only show up at runtime. It makes no model
call and needs no API key: you apply the fix hints.

## Run it

1. **Get Probe.** The plugin ships no scripts. Run this block with the Bash tool: it downloads the pinned release from GitHub,
checks it against the release's `checksums.txt` (a mismatch installs nothing), keeps it in `~/.trustabl-probe/`, and
prints `PROBE_BIN=<path>`. Later runs only check the version, so run it at the start of each session that uses
Probe. Tell the user what it downloads the first time. Do not use an `autofix` found on `PATH`: the name is too generic to trust as Probe.

```bash
V=0.5.0; D="$HOME/.trustabl-probe/v$V"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) OS=windows; EXT=zip; EXE=autofix.exe ;; Darwin) OS=darwin; EXT=tar.gz; EXE=autofix ;; *) OS=linux; EXT=tar.gz; EXE=autofix ;; esac
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; *) ARCH=amd64 ;; esac; [ "$OS" = windows ] && ARCH=amd64
PROBE_BIN="$D/$EXE"
if ! "$PROBE_BIN" version 2>/dev/null | head -n1 | grep -q "$V\$"; then
  A="autofix_${V}_${OS}_${ARCH}.$EXT"; U="https://github.com/trustabl/agent-network-access-probe/releases/download/v$V"; T="$(mktemp -d)"
  curl -fsSL "$U/$A" -o "$T/$A" && curl -fsSL "$U/checksums.txt" -o "$T/checksums.txt" &&
  SUM=sha256sum; command -v sha256sum >/dev/null || SUM="shasum -a 256"
  (cd "$T" && L="$(grep " $A\$" checksums.txt)" && [ -n "$L" ] && echo "$L" | $SUM -c -) &&
  mkdir -p "$D" && if [ "$EXT" = zip ]; then unzip -oq "$T/$A" -d "$D"; else tar -xzf "$T/$A" -C "$D"; fi &&
  chmod +x "$PROBE_BIN"; rm -rf "$T"
fi
if "$PROBE_BIN" version 2>/dev/null | head -n1 | grep -q "$V\$"; then echo "PROBE_BIN=$PROBE_BIN"; else echo "install failed: see the message above"; fi
```

Shell state does not carry between Bash calls: start each later command with `PROBE_BIN="<the printed path>";`.
If the block prints `install failed`, show the user the message above it and stop.
2. **Pick the sandbox.** Run `docker info --format '{{.ServerVersion}}'`. If it
   prints a version, Docker is running and the scan can use the sandbox. If not,
   scan static only and tell the user that starting Docker enables the sandbox.
   Never install or start Docker yourself; Docker Desktop needs admin rights.
3. **Scan** the directory the user named, else the current one:
   ```bash
   "$PROBE_BIN" fix --source <dir> --no-sign --output json                                  # static only
   "$PROBE_BIN" fix --source <dir> --no-sign --output json --sandbox --runner docker        # with the sandbox
   ```
   Add `--entrypoint <file>` per entry point when the user names them (default:
   Probe finds them). Add `--allow-write-tools` **only when the user asks**: it
   runs tools that look destructive (network writes, deletes, payments) in the
   sandbox, ideally with staging credentials. The first sandbox run also pulls
   the images (`python:3-slim`, `node:20-slim`, `golang:1.25-alpine`, `ruby:3-slim`).
4. **Read the reports** Probe writes into the scanned directory:
   - `autofix-attestation.json`: `production_readiness_score` (0-100),
     `network_calls` (the allow list as host and port), `languages_detected`.
   - `probe.findings.json`: `findings`, each with `severity`, `title`, `file`,
     `fix_hint` and `evidence`.
   - `network_policies.draft.yaml`: the draft OpenShell network policy.
   - `probe.profile.json`: a tool with a `harness_id` ran in the sandbox.

## Report

1. **Readiness** score, the number of findings by severity, and whether the
   sandbox ran (or why not).
2. **The allow list**, one `host:port` per line, and where the draft policy file is.
3. **Findings, worst first** (critical, warning, info): title, file, and the fix
   hint in a sentence.
4. If a finding says "Sandbox execution skipped", a tool looked destructive and
   was analyzed statically only; offer the `--allow-write-tools` run.

## Fix

Apply each fix hint yourself, showing the diff first and keeping each change to
what the finding calls for. Leave anything that needs a judgement about the
system, such as which hosts a tool should really reach, and say why. Then scan
again and report what changed.
