# agent-network-access-probe

A plugin for Claude Code and Cursor that adds Trustabl Probe as an MCP server.
Your coding agent uses it to see what an agent tool can reach on the network and
to catch runtime problems before you ship the tool.

## What it does

- Drafts a least-privilege network allow list (an OpenShell `network_policies`
  draft) from the tool's code.
- When a sandbox is available, runs the tool locally with its network blocked and
  reports crashes, missing dependencies and blocked connection attempts.
- Returns findings with fix hints for your agent to apply. It makes no model call
  and needs no API key.

## Tools

- `probe_check_setup`: read-only report of what Probe needs on this machine and
  what is missing.
- `probe_install`: downloads the checksum-verified Probe binary and pulls the
  sandbox images.
- `probe_scan`: readiness score, draft allow list, and findings with fix hints.

## Requirements

Node.js 18 or later. Docker is optional and enables the sandbox; without it, scans
run static analysis only. The server never installs Docker, OpenShell or Python
itself: it returns the command, and your agent should ask you before running it.

## What it changes on your machine

- Downloads the Probe binary from the matching GitHub release into
  `~/.trustabl-probe/<version>/`, after checking it against the release
  `checksums.txt`.
- Pulls the sandbox images (`python:3-slim`, `node:20-slim`, `golang:1.25-alpine`,
  `ruby:3-slim`) when you run `probe_install` or on the first sandbox run.
- Writes `network_policies.draft.yaml`, `probe.findings.json`, `probe.profile.json`
  and `autofix-attestation.json` into the scanned folder.
- Caches sandbox results in your user cache folder under `trustabl-probe/results`.

## Privacy

- **Collection:** none. No telemetry, no model calls, nothing is sent to Trustabl.
- **Your code:** read and analyzed on your machine and never uploaded. Signing is
  turned off, so nothing goes to a transparency log.
- **Network access:** only GitHub (to download the Probe release), Docker Hub (for
  the sandbox images) and, when a Python tool declares dependencies, PyPI to
  install them before the sandbox run. The tool under test runs with its network
  blocked.
- **Storage:** the Probe binary in `~/.trustabl-probe/`, sandbox results in your
  user cache folder under `trustabl-probe/results`, and the four report files in
  the scanned folder. Delete any of them at any time.
- **Third parties:** nothing is shared with Trustabl or anyone else.
- **Trustabl's privacy policy** (for its hosted services): https://trustabl.ai/privacy/
- **Contact:** https://github.com/trustabl/agent-network-access-probe/issues

## More

Server details: [mcp/README.md](../README.md). The Probe command-line tool:
[README.md](../../README.md). License: Apache-2.0.
