# Trustabl Probe MCP server

Gives your coding agent [Trustabl Probe](https://github.com/trustabl/agent-network-access-probe):
it drafts a network allow list for an agent tool and runs the tool in a
network-blocked sandbox to catch problems that only show up at runtime. Every
finding comes with a fix hint, and your agent applies the fixes, so no model or
API key is needed.

## Tools

| Tool | What it does | Changes anything? |
|---|---|---|
| `probe_check_setup` | Reports whether the Probe binary, Docker and the sandbox images are ready, which languages can run in the sandbox, and the exact command to fix each missing piece. | No |
| `probe_install` | Downloads the Probe binary (checksum-verified) and pulls the sandbox images. For Docker, OpenShell or Python it only returns the command to run, with its caveats. | Yes, see below |
| `probe_scan` | Scans a tool directory and returns a readiness score, the draft network allow list, and findings worst-first with fix hints. | Writes four report files into the scanned directory |

### Static and sandbox

- **Static** reads the code and flags problems such as missing timeouts, hardcoded
  credentials or unfiltered tool output. It also drafts the network allow list
  (an OpenShell network policy) from the code. It always runs and needs nothing
  extra.
- **Sandbox** also runs the tool with its network blocked, catching crashes,
  missing dependencies and blocked connection attempts. It needs Docker (or
  NVIDIA OpenShell). With `sandbox: "auto"`, the default, it runs whenever a
  runner is ready. Tools that look destructive (payments, deletes, network
  writes) are not run unless you pass `allow_write_tools: true`.

Docker covers Python, JavaScript/TypeScript, Go and Ruby; the OpenShell image runs
Python and Node. Shell scripts are always analyzed statically only.

## Install

Requires Node.js 18 or later. Docker is optional and enables the sandbox.

The server ships with every [Probe release](https://github.com/trustabl/agent-network-access-probe/releases)
as `trustabl-probe-mcp-<version>.tgz`. The examples use v0.2.4; use the latest
release.

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "trustabl-probe": {
      "command": "npx",
      "args": ["-y", "https://github.com/trustabl/agent-network-access-probe/releases/download/v0.2.4/trustabl-probe-mcp-0.2.4.tgz"]
    }
  }
}
```

**Claude Code:**

```bash
claude mcp add trustabl-probe -- npx -y https://github.com/trustabl/agent-network-access-probe/releases/download/v0.2.4/trustabl-probe-mcp-0.2.4.tgz
```

**Claude Desktop** (`claude_desktop_config.json`): the same `command` and `args`
as the Cursor example, under `mcpServers`.

Then ask your agent to run `probe_check_setup`.

## What it changes on your machine

- Downloads the Probe binary from the same release as the server into
  `~/.trustabl-probe/<version>/`, after checking it against the release
  `checksums.txt`. A mismatch is a hard failure.
- Pulls the sandbox images (`python:3-slim`, `node:20-slim`, `golang:1.25-alpine`,
  `ruby:3-slim`) when you run `probe_install`, or on the first sandbox run.
- Writes `network_policies.draft.yaml`, `probe.findings.json`, `probe.profile.json`
  and `autofix-attestation.json` into the scanned directory.
- Never installs Docker, OpenShell or Python itself. It returns the command, and
  your agent should ask you before running it. Docker Desktop needs admin rights,
  may need a restart on Windows, and needs a paid subscription for larger
  companies.

## Privacy

Everything runs on your machine. The scanned code is not sent anywhere: there is
no model call, and attestation signing is turned off, so nothing goes to a
transparency log. The only network access is to GitHub (to find and download the
Probe release), Docker Hub (for the images) and, when a Python tool declares
dependencies, PyPI to install them before the sandbox run. The tool under test
itself runs with its network blocked.

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `PROBE_VERSION` | the release the server came with | Probe release to use instead, e.g. `v0.2.3` or `latest`. Needs v0.2.3 or later. |
| `PROBE_BIN` | | Path to a local Probe build; skips the download |
| `GITHUB_TOKEN` | | Only to avoid GitHub's anonymous rate limit when `PROBE_VERSION` is `latest` |

## Development

From `mcp/`:

```bash
cd server && npm ci && npm run build   # bundles to dist/index.js, which is committed
node test/smoke.mjs                    # handshake, tools/list, setup check
SMOKE_SCAN=1 node test/smoke.mjs       # also a static scan of test/fixture with the released Probe
PROBE_BIN=/path/to/autofix node test/smoke.mjs   # the same scan with a local Probe build
```

A checkout has version `0.0.0` and uses the latest Probe release. The release
workflow sets the real version when it packs the server.

## License

Apache-2.0, like Probe.
