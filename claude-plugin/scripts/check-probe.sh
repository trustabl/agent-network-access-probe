#!/usr/bin/env bash
# Probe plugin — SessionStart bootstrap.
#
# Installs the pinned Probe binary (`autofix`) into the plugin's private data
# dir, checksum-verified, and exposes it to the session as $PROBE_BIN. The
# probe-scan skill runs scans through that binary with the Bash tool; this
# plugin has no MCP server (the Claude Directory accepts local MCP servers only
# from verified organizations; the MCP server lives on for Cursor and MCP clients).
#
# This script ALWAYS exits 0 and never fails the session.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-probe.sh
. "${DIR}/lib-probe.sh"

if bin="$(tdl_managed_bin)" && [ -n "$bin" ] && tdl_ensure; then
  if [ -n "${CLAUDE_ENV_FILE:-}" ] && ! grep -q 'PROBE_BIN=' "$CLAUDE_ENV_FILE" 2>/dev/null; then
    echo "export PROBE_BIN=\"$bin\"" >> "$CLAUDE_ENV_FILE"
  fi
  echo "[probe] Trustabl Probe ${TDL_VERSION} ready at ${bin}. Scan with \"\$PROBE_BIN\" fix --source <dir> --no-sign --output json."
  exit 0
fi

# An `autofix` already on PATH is not used: the name is too generic to trust as Probe.
echo "[probe] could not install Trustabl Probe automatically (offline, or no curl / tar / unzip); ${TDL_HINT}."
exit 0
