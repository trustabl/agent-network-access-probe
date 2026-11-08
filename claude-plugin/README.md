# agent-network-access-probe for Claude Code

A Claude Code plugin that gives your coding agent Trustabl Probe: see what an agent
tool can reach on the network, and catch runtime problems before you ship it.

## What it does

- Drafts a least-privilege network allow list (an OpenShell `network_policies`
  draft) from the tool's code.
- When Docker is running, runs the tool locally with its network blocked and
  reports crashes, missing dependencies and blocked connection attempts.
- Returns findings with fix hints for your agent to apply. It makes no model call
  and needs no API key.

Use it with `/agent-network-access-probe:scan [dir]`, or just ask Claude to check
an agent tool; the `probe-scan` skill takes it from there.

## How it runs

The plugin has no MCP server, hooks or scripts. On first use, Claude runs a short install block from the
skill that downloads the pinned Probe binary into `~/.trustabl-probe/`, after checking it against the release
`checksums.txt` (a mismatch installs nothing), and then runs it with the Bash tool. It works on macOS, Linux and Windows (Git Bash). For Cursor and other MCP
clients, use the MCP server instead: [mcp/README.md](../mcp/README.md).

## Requirements

Nothing beyond Claude Code. Docker is optional and enables the sandbox; without
it, scans run static analysis only. The plugin never installs or starts Docker.

## What it changes on your machine

- Installs the Probe binary into `~/.trustabl-probe/` (shared with the Probe MCP server).
- Pulls the sandbox images (`python:3-slim`, `node:20-slim`, `golang:1.25-alpine`,
  `ruby:3-slim`) on the first sandbox run.
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
- **Storage:** the Probe binary in `~/.trustabl-probe/`, sandbox results in
  your user cache folder under `trustabl-probe/results`, and the four report files
  in the scanned folder. Delete any of them at any time.
- **Third parties:** nothing is shared with Trustabl or anyone else.
- **Trustabl's privacy policy** (for its hosted services): https://trustabl.ai/privacy/
- **Contact:** https://github.com/trustabl/agent-network-access-probe/issues

License: Apache-2.0.
