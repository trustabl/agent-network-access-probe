// Resolves a usable Probe (`autofix`) binary for the current machine.
//
// Order: PROBE_BIN override -> cached release -> download the release asset for
// this OS/arch, sha256-verify it against the release `checksums.txt`, and cache
// it under ~/.trustabl-probe/<version>/. An `autofix` already on PATH is not
// used: the name is too generic to trust as Probe.
//
// The server ships inside Probe's own release, so by default it runs the Probe
// from that same release (its package.json version). A dev checkout (0.0.0)
// uses the latest release instead.
//
// NOTE: everything here logs to stderr. stdout is the MCP protocol channel.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const REPO = "trustabl/agent-network-access-probe";
export const CACHE_ROOT = path.join(os.homedir(), ".trustabl-probe");
const log = (msg) => process.stderr.write(`[probe] ${msg}\n`);

/**
 * Optional settings arrive as ${VAR} placeholders that the host substitutes.
 * A host that leaves an unset one unsubstituted hands us the literal
 * "${PROBE_VERSION}"; treat that as "not set" rather than as a value.
 */
export const setting = (value) => {
  const v = value?.trim();
  return v && !/^\$\{[^}]*\}$/.test(v) ? v : undefined;
};

function ghHeaders() {
  const h = { "User-Agent": "trustabl-agent-network-access-probe" };
  const token = setting(process.env.GITHUB_TOKEN);
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

/** linux/darwin/windows + amd64/arm64, matching the Probe release matrix. */
function platformTarget() {
  const osName = { linux: "linux", darwin: "darwin", win32: "windows" }[process.platform];
  if (!osName) throw new Error(`Unsupported OS: ${process.platform}`);
  const arch = { x64: "amd64", arm64: "arm64" }[process.arch];
  if (!arch) throw new Error(`Unsupported architecture: ${process.arch}`);
  // Windows releases are amd64-only (arm64 Windows runs the amd64 build via emulation).
  const assetArch = osName === "windows" ? "amd64" : arch;
  const ext = osName === "windows" ? "zip" : "tar.gz";
  const exe = osName === "windows" ? "autofix.exe" : "autofix";
  return { osName, arch: assetArch, ext, exe };
}

/** `autofix version` output, or null if the binary does not run. */
export function probeVersion(bin) {
  const r = spawnSync(bin, ["version"], { encoding: "utf8", shell: false });
  if (r.error || r.status !== 0) return null;
  return r.stdout.trim().split(/\s+/).pop() || "unknown";
}

/**
 * The binary that would be used right now, without downloading anything:
 * the PROBE_BIN override, else the newest cached release. Used by the
 * read-only setup check.
 */
export function installedProbe() {
  const override = setting(process.env.PROBE_BIN);
  if (override) return { bin: override, source: "PROBE_BIN" };
  const { exe } = platformTarget();
  let versions = [];
  try {
    versions = fs.readdirSync(CACHE_ROOT).filter((v) => fs.existsSync(path.join(CACHE_ROOT, v, exe)));
  } catch {
    return null;
  }
  if (!versions.length) return null;
  const newest = versions.sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).pop();
  return { bin: path.join(CACHE_ROOT, newest, exe), source: `cache (${newest})` };
}

async function resolveVersion(requested) {
  if (requested && requested !== "latest") return requested.startsWith("v") ? requested : `v${requested}`;
  const res = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers: ghHeaders() });
  if (!res.ok) {
    throw new Error(
      `Could not resolve the latest Probe release (HTTP ${res.status}). ` +
        `Set PROBE_VERSION to a tag (e.g. v0.2.3), or set GITHUB_TOKEN if you are rate-limited.`
    );
  }
  const tag = (await res.json()).tag_name;
  if (!tag) throw new Error("Latest Probe release has no tag_name.");
  return tag;
}

async function download(url, dest) {
  const res = await fetch(url, {
    headers: { ...ghHeaders(), Accept: "application/octet-stream" },
    redirect: "follow",
  });
  if (!res.ok) throw new Error(`Download failed (HTTP ${res.status}): ${url}`);
  fs.writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
}

/**
 * sha256-verify the archive against the release checksums.txt. A missing
 * checksums file is a hard failure: we do not run an unverified binary.
 */
async function verifyChecksum(archivePath, assetName, version) {
  const url = `https://github.com/${REPO}/releases/download/${version}/checksums.txt`;
  const res = await fetch(url, { headers: ghHeaders(), redirect: "follow" });
  if (!res.ok) throw new Error(`Could not fetch checksums.txt (HTTP ${res.status}); refusing to run an unverified binary.`);
  const line = (await res.text()).split("\n").find((l) => l.trim().endsWith(assetName));
  if (!line) throw new Error(`${assetName} is not listed in checksums.txt; refusing to run an unverified binary.`);
  const expected = line.trim().split(/\s+/)[0];
  const actual = createHash("sha256").update(fs.readFileSync(archivePath)).digest("hex");
  if (expected !== actual) throw new Error(`Checksum mismatch for ${assetName}: expected ${expected}, got ${actual}`);
  log(`checksum verified: ${assetName}`);
}

/**
 * Windows releases ship a .zip, every other platform a .tar.gz. GNU tar (e.g.
 * under Git Bash) cannot read zip, so Windows uses PowerShell's Expand-Archive.
 */
function extract(archivePath, destDir) {
  const [cmd, args] =
    process.platform === "win32"
      ? [
          "powershell",
          [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${destDir}' -Force`,
          ],
        ]
      : ["tar", ["-xf", archivePath, "-C", destDir]];
  const r = spawnSync(cmd, args, { encoding: "utf8" });
  if (r.error) throw new Error(`Could not extract ${path.basename(archivePath)}: ${r.error.message}`);
  if (r.status !== 0) {
    throw new Error(`Could not extract ${path.basename(archivePath)}: ${r.stderr?.trim() || `exit ${r.status}`}`);
  }
}

/** The Probe release this server was packed with, e.g. "v0.2.4"; none in a dev checkout. */
export function releaseVersion() {
  try {
    const { version } = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    return version && version !== "0.0.0" ? `v${version}` : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Returns an absolute path to a runnable Probe binary, downloading and
 * verifying it on first use. Cached per version.
 */
export async function ensureProbe() {
  const override = setting(process.env.PROBE_BIN);
  if (override) {
    if (!probeVersion(override)) throw new Error(`PROBE_BIN is set to ${override}, but it does not run.`);
    return override;
  }

  const { osName, arch, ext, exe } = platformTarget();
  let version;
  try {
    version = await resolveVersion(setting(process.env.PROBE_VERSION) ?? releaseVersion());
  } catch (err) {
    // Offline or rate-limited: a cached release still works.
    const cached = installedProbe();
    if (!cached) throw err;
    log(`${err.message} Using the cached binary from ${cached.source}.`);
    return cached.bin;
  }
  const cacheDir = path.join(CACHE_ROOT, version);
  const binPath = path.join(cacheDir, exe);
  if (fs.existsSync(binPath)) return binPath;

  const assetName = `autofix_${version.replace(/^v/, "")}_${osName}_${arch}.${ext}`;
  fs.mkdirSync(cacheDir, { recursive: true });
  const archivePath = path.join(cacheDir, assetName);

  log(`downloading ${assetName} (${version})...`);
  await download(`https://github.com/${REPO}/releases/download/${version}/${assetName}`, archivePath);
  await verifyChecksum(archivePath, assetName, version);
  extract(archivePath, cacheDir);
  fs.rmSync(archivePath, { force: true });

  if (!fs.existsSync(binPath)) throw new Error(`Extracted ${assetName} but ${exe} was not found in ${cacheDir}`);
  if (osName !== "windows") fs.chmodSync(binPath, 0o755);
  log(`installed Probe ${version}`);
  return binPath;
}
