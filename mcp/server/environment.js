// What Probe needs on this machine, checked without changing anything, and the
// exact command that fixes each missing piece.
//
// Probe's own pieces (the binary, the sandbox images) are installed by the
// install tool. System software (Docker, OpenShell, Python) is never installed
// here: we return the command and the calling agent asks the user to run it.

import { spawnSync } from "node:child_process";
import { installedProbe, probeVersion } from "./probe-bin.js";

// The Docker runner's base image per language (sandbox.dockerBaseImage in Probe).
export const SANDBOX_IMAGES = {
  python: "python:3-slim",
  node: "node:20-slim",
  go: "golang:1.25-alpine",
  ruby: "ruby:3-slim",
};

function run(cmd, args, timeout = 15000) {
  const r = spawnSync(cmd, args, { encoding: "utf8", timeout, shell: false, windowsHide: true });
  return {
    found: !(r.error && r.error.code === "ENOENT"),
    ok: !r.error && r.status === 0,
    out: (r.stdout || "").trim(),
  };
}

/** The python the OpenShell runner uses: python3, else python (as in Probe). */
function hostPython() {
  for (const cmd of ["python3", "python"]) {
    if (run(cmd, ["-m", "pip", "--version"]).ok) return cmd;
  }
  return null;
}

/** Read-only snapshot of everything Probe needs. */
export function checkSetup() {
  const installed = installedProbe();
  const version = installed && probeVersion(installed.bin);
  const probe = { ok: Boolean(version), version, bin: installed?.bin ?? null, source: installed?.source ?? null };

  const cli = run("docker", ["--version"]);
  const info = cli.ok ? run("docker", ["info", "--format", "{{.ServerVersion}}"], 30000) : { ok: false };
  const docker = { cli: cli.ok, daemon: info.ok, version: info.ok ? info.out : null };

  const images = {};
  if (docker.daemon) {
    for (const image of Object.values(SANDBOX_IMAGES)) {
      images[image] = run("docker", ["image", "inspect", image, "--format", "{{.Id}}"]).ok;
    }
  }

  const osh = run("openshell", ["--help"]);
  const openshell = { cli: osh.found, gateway: osh.found && run("openshell", ["sandbox", "list"], 30000).ok };
  const python = hostPython();

  // Docker covers every language Probe sandboxes; OpenShell's image only runs
  // Python and Node. Shell scripts are never sandboxed, by Probe's design.
  let sandbox = { runner: null, languages: [] };
  if (docker.daemon) sandbox = { runner: "docker", languages: ["python", "javascript/typescript", "go", "ruby"] };
  else if (openshell.gateway && python) sandbox = { runner: "openshell", languages: ["python", "javascript/typescript"] };

  return { probe, docker, images, openshell, python: { ok: Boolean(python), cmd: python }, sandbox };
}

const DOCKER_DESKTOP_NOTE =
  "Docker Desktop needs a paid subscription for larger companies; check https://www.docker.com/pricing/ first.";

function installDocker(platform) {
  if (platform === "win32")
    return {
      command: "winget install -e --id Docker.DockerDesktop",
      notes: ["Needs admin rights.", "Uses WSL 2 and may ask for a restart.", DOCKER_DESKTOP_NOTE],
    };
  if (platform === "darwin")
    return { command: "brew install --cask docker && open -a Docker", notes: [DOCKER_DESKTOP_NOTE] };
  return {
    command: "curl -fsSL https://get.docker.com | sudo sh",
    notes: ["Needs sudo.", "Docker's own install guide: https://docs.docker.com/engine/install/"],
  };
}

function startDocker(platform) {
  if (platform === "win32") return 'Start-Process "$env:ProgramFiles\\Docker\\Docker\\Docker Desktop.exe"';
  if (platform === "darwin") return "open -a Docker";
  return "sudo systemctl start docker";
}

function installPython(platform) {
  if (platform === "win32") return "winget install -e --id Python.Python.3.12";
  if (platform === "darwin") return "brew install python";
  return "sudo apt-get install -y python3 python3-pip";
}

/**
 * What is missing, in the order to fix it. `automatic` steps are done by the
 * install tool; `you` steps are commands for the user (or their agent, with
 * the user's permission) to run.
 */
export function nextSteps(setup, platform = process.platform) {
  const steps = [];
  if (!setup.probe.ok) {
    steps.push({ item: "Probe binary", who: "automatic", action: "Run probe_install to download and verify it." });
  }
  if (!setup.docker.cli) {
    const d = installDocker(platform);
    steps.push({ item: "Docker", who: "you", action: d.command, notes: d.notes, why: "Needed for sandbox runs." });
  } else if (!setup.docker.daemon) {
    steps.push({
      item: "Docker daemon",
      who: "you",
      action: startDocker(platform),
      why: "Docker is installed but not running.",
      notes: platform === "win32" ? ["Run it in PowerShell."] : [],
    });
  } else {
    const missing = Object.entries(setup.images).filter(([, ok]) => !ok).map(([image]) => image);
    if (missing.length) {
      steps.push({
        item: "Sandbox images",
        who: "automatic",
        action: `Run probe_install to pull ${missing.join(", ")}.`,
        why: "Otherwise the first sandbox run pulls them and can take a minute.",
      });
    }
  }
  if (setup.openshell.cli && !setup.openshell.gateway) {
    steps.push({
      item: "OpenShell gateway",
      who: "you",
      action: "openshell gateway start",
      why: "Optional: only for the OpenShell runner. Keep it running in a separate terminal.",
    });
  }
  if (setup.openshell.cli && !setup.python.ok) {
    steps.push({
      item: "Python 3 with pip",
      who: "you",
      action: installPython(platform),
      why: "Optional: the OpenShell runner uses it to download the tool's dependencies.",
    });
  }
  return steps;
}
