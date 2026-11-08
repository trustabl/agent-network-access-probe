# shellcheck shell=bash
# Install logic for the plugin's pinned CLI, sourced by the SessionStart hook
# (check-probe.sh). It downloads the release asset for this OS and
# architecture into the plugin's private data dir, verifies it against the
# release's checksums.txt, and installs it atomically. It runs on macOS, Linux
# and Windows (Git Bash, which Claude Code uses there).
#
# Every function writes diagnostics to STDERR only, never stdout.

# Pinned Probe release. Bump it on every Probe release so plugin users stay on
# the latest version. The pin stays exact so the checksum check means something.
TDL_TOOL="autofix"
TDL_VERSION="0.5.0"
TDL_REPO="trustabl/agent-network-access-probe"
TDL_HINT="download it from https://github.com/${TDL_REPO}/releases"

_tdl_log()     { printf '[%s] %s\n' "$TDL_TOOL" "$*" >&2; }
_tdl_have()    { command -v "$1" >/dev/null 2>&1; }
_tdl_windows() { case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) return 0 ;; esac; return 1; }

# Absolute path to the plugin-managed binary ("" when there is no data dir).
tdl_managed_bin() {
  [ -n "${CLAUDE_PLUGIN_DATA:-}" ] || return 0
  if _tdl_windows; then printf '%s' "${CLAUDE_PLUGIN_DATA}/bin/${TDL_TOOL}.exe"
  else printf '%s' "${CLAUDE_PLUGIN_DATA}/bin/${TDL_TOOL}"; fi
}

# Version reported by the binary at $1 ("" if absent). The version is the last
# word of the first line ("Trustabl 0.1.15", or just "0.5.0").
tdl_bin_version() { [ -x "$1" ] && "$1" version 2>/dev/null | awk 'NR==1 {v=$NF; sub(/^v/, "", v); print v}'; }

# Ensure the pinned binary is installed at the managed path. Returns 0 when it
# is present and exactly TDL_VERSION, 1 otherwise. Idempotent.
tdl_ensure() {
  local bin; bin="$(tdl_managed_bin)"
  [ -n "$bin" ] || { _tdl_log "no CLAUDE_PLUGIN_DATA set; cannot manage a private binary."; return 1; }
  [ "$(tdl_bin_version "$bin")" = "$TDL_VERSION" ] && return 0

  local os arch ext exe=""
  case "$(uname -s)" in
    Darwin) os=darwin ;;
    Linux)  os=linux ;;
    MINGW*|MSYS*|CYGWIN*) os=windows ;;
    *) _tdl_log "auto-install is unsupported on '$(uname -s)'."; return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64)  arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) _tdl_log "auto-install is unsupported on arch '$(uname -m)'."; return 1 ;;
  esac
  if [ "$os" = windows ]; then
    arch=amd64 ext=zip exe=.exe  # ponytail: Windows releases are amd64 only; arm64 runs it under emulation
    { _tdl_have unzip || _tdl_have powershell.exe; } || { _tdl_log "auto-install needs unzip or PowerShell."; return 1; }
  else
    ext=tar.gz
    _tdl_have tar || { _tdl_log "auto-install needs tar."; return 1; }
  fi
  _tdl_have curl || { _tdl_log "auto-install needs curl."; return 1; }
  { _tdl_have sha256sum || _tdl_have shasum; } || { _tdl_log "auto-install needs sha256sum or shasum."; return 1; }

  local asset base
  asset="${TDL_TOOL}_${TDL_VERSION}_${os}_${arch}.${ext}"
  base="https://github.com/${TDL_REPO}/releases/download/v${TDL_VERSION}"
  mkdir -p "$(dirname "$bin")" || { _tdl_log "could not create $(dirname "$bin")."; return 1; }

  # Download, verify and stage in a subshell so its temp dir is always cleaned
  # up. Staging sits next to the binary, so the final mv is atomic.
  (
    tmp="$(mktemp -d)" || exit 1
    stage="$(dirname "$bin")/.${TDL_TOOL}.staging.${BASHPID:-$$}"
    trap 'rm -rf "$tmp" "$stage"' EXIT
    curl -fsSL "${base}/${asset}"      -o "${tmp}/${asset}"      || { _tdl_log "download of ${asset} failed (offline?)."; exit 1; }
    curl -fsSL "${base}/checksums.txt" -o "${tmp}/checksums.txt" || { _tdl_log "download of checksums.txt failed."; exit 1; }
    want="$(awk -v f="$asset" '$2==f || $2=="*"f {print $1}' "${tmp}/checksums.txt" | head -n1)"
    if _tdl_have sha256sum; then got="$(sha256sum "${tmp}/${asset}" | awk '{print $1}')"
    else                        got="$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')"; fi
    [ -n "$want" ] && [ "$want" = "$got" ] || { _tdl_log "checksum verification FAILED for ${asset}; nothing was installed."; exit 1; }
    if [ "$ext" = zip ]; then
      unzip -o -q "${tmp}/${asset}" -d "$tmp" 2>/dev/null ||
        powershell.exe -NoProfile -NonInteractive -Command \
          "Expand-Archive -LiteralPath '$(cygpath -w "${tmp}/${asset}")' -DestinationPath '$(cygpath -w "$tmp")' -Force" >/dev/null 2>&1
    else
      tar -xzf "${tmp}/${asset}" -C "$tmp" 2>/dev/null
    fi
    src="$(find "$tmp" -type f -name "${TDL_TOOL}${exe}" 2>/dev/null | head -n1)"
    [ -n "$src" ] || { _tdl_log "could not find ${TDL_TOOL}${exe} inside ${asset}."; exit 1; }
    install -m 0755 "$src" "$stage" 2>/dev/null || { cp "$src" "$stage" && chmod 0755 "$stage"; } || { _tdl_log "staging the binary failed."; exit 1; }
    mv -f "$stage" "$bin" || { _tdl_log "installing to ${bin} failed."; exit 1; }
    exit 0
  ) || return 1

  [ "$(tdl_bin_version "$bin")" = "$TDL_VERSION" ] || { _tdl_log "post-install version check failed."; return 1; }
  _tdl_log "installed ${TDL_TOOL} ${TDL_VERSION} at ${bin}."
  return 0
}
