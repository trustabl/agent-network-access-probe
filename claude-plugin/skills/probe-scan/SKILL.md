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

The `SessionStart` hook installs the pinned Probe binary (checksum-verified) and
exports it as `$PROBE_BIN`. If it is empty, the install failed: say so, show the
hook's `[probe]` message, and stop. Do not use an `autofix` found on `PATH`.

1. **Pick the sandbox.** Run `docker info --format '{{.ServerVersion}}'`. If it
   prints a version, Docker is running and the scan can use the sandbox. If not,
   scan static only and tell the user that starting Docker enables the sandbox.
   Never install or start Docker yourself; Docker Desktop needs admin rights.
2. **Scan** the directory the user named, else the current one:
   ```bash
   "$PROBE_BIN" fix --source <dir> --no-sign --output json                                  # static only
   "$PROBE_BIN" fix --source <dir> --no-sign --output json --sandbox --runner docker        # with the sandbox
   ```
   Add `--entrypoint <file>` per entry point when the user names them (default:
   Probe finds them). Add `--allow-write-tools` **only when the user asks**: it
   runs tools that look destructive (network writes, deletes, payments) in the
   sandbox, ideally with staging credentials. The first sandbox run also pulls
   the images (`python:3-slim`, `node:20-slim`, `golang:1.25-alpine`, `ruby:3-slim`).
3. **Read the reports** Probe writes into the scanned directory:
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
