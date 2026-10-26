#!/usr/bin/env node
// Trustabl Probe MCP server: exposes Probe to the agent as three tools.
//
//   probe_check_setup  read-only: what Probe needs on this machine, what is missing
//   probe_install      install Probe's own pieces (binary, sandbox images);
//                      returns the commands for system software, never runs them
//   probe_scan         scan an agent tool: findings with fix hints, the draft
//                      network allow list, and a sandbox run when one is ready
//
// Probe runs without a model here: the calling agent applies the fix hints.
// stdout is reserved for the MCP protocol; all logging goes to stderr.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

import { SANDBOX_IMAGES, checkSetup, nextSteps } from "./environment.js";
import { ensureProbe, probeVersion, releaseVersion } from "./probe-bin.js";

const log = (msg) => process.stderr.write(`[probe] ${msg}\n`);
const textResult = (text, isError = false) => ({ content: [{ type: "text", text }], isError });

const SEVERITY_RANK = { critical: 3, warning: 2, info: 1 };
// Enough for the agent to act on; the rest stays in probe.findings.json.
const MAX_FINDINGS_RETURNED = 50;
const MAX_EVIDENCE_PER_FINDING = 3;
const MAX_EVIDENCE_CHARS = 300;
const SCAN_TIMEOUT_MS = 10 * 60 * 1000;
const PULL_TIMEOUT_MS = 10 * 60 * 1000;

// eslint-disable-next-line no-control-regex
const stripAnsi = (s) => s.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").replace(/\r/g, "");
const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Rendering

function setupTable(s) {
  const pulled = Object.values(s.images).filter(Boolean).length;
  const rows = [
    ["Probe binary", s.probe.ok ? `ready (${s.probe.version}, ${s.probe.source})` : "missing"],
    [
      "Docker",
      s.docker.daemon ? `running (${s.docker.version})` : s.docker.cli ? "installed, not running" : "not installed",
    ],
    ["Sandbox images", s.docker.daemon ? `${pulled} of ${Object.keys(s.images).length} pulled` : "n/a (Docker not running)"],
    [
      "OpenShell (optional)",
      s.openshell.gateway ? "gateway running" : s.openshell.cli ? "installed, gateway stopped" : "not installed",
    ],
    ["Python 3 with pip (OpenShell only)", s.python.ok ? `ready (${s.python.cmd})` : "missing"],
  ];
  return ["| Piece | Status |", "|---|---|", ...rows.map(([k, v]) => `| ${k} | ${v} |`)].join("\n");
}

function sandboxLine(s) {
  return s.sandbox.runner
    ? `**Sandbox:** ready via ${s.sandbox.runner} (${s.sandbox.languages.join(", ")}). Shell scripts are always static only.`
    : "**Sandbox:** not available, so scans run static analysis only. Start or install Docker to enable it.";
}

function stepsList(steps) {
  if (!steps.length) return "Nothing missing.";
  return steps
    .map((st, i) => {
      const head =
        st.who === "you"
          ? `${i + 1}. **${st.item}**, for you to run: \`${st.action}\``
          : `${i + 1}. **${st.item}**: ${st.action}`;
      const extra = [st.why, ...(st.notes ?? [])].filter(Boolean).map((n) => `   - ${n}`);
      return [head, ...extra].join("\n");
    })
    .join("\n");
}

// ---------------------------------------------------------------------------

const server = new McpServer({ name: "trustabl-probe", version: releaseVersion()?.slice(1) ?? "dev" });

server.registerTool(
  "probe_check_setup",
  {
    title: "Check what Probe needs on this machine",
    description:
      "Read-only. Reports whether the Probe binary, Docker (running), the sandbox images, and the " +
      "optional OpenShell runner are ready, which languages can run in the sandbox, and the exact " +
      "command to fix each missing piece. Changes nothing. Run it before probe_install or when a " +
      "scan says the sandbox is unavailable.",
    inputSchema: {},
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  async () => {
    const setup = checkSetup();
    const steps = nextSteps(setup);
    return textResult(
      [
        "## Probe setup",
        "",
        setupTable(setup),
        "",
        sandboxLine(setup),
        "",
        "### Next steps",
        stepsList(steps),
        ...(steps.some((st) => st.who === "you")
          ? ["", "Steps for you install or start system software. Ask the user before running them."]
          : []),
      ].join("\n")
    );
  }
);

server.registerTool(
  "probe_install",
  {
    title: "Install Probe's own pieces",
    description:
      "Downloads the Probe binary from its GitHub release (checksum-verified) and, when Docker is " +
      "running, pulls the sandbox base images. It never installs system software: for Docker, " +
      "OpenShell or Python it returns the exact command and its caveats (admin rights, restarts, " +
      "licensing) for you to show the user and run only with their permission. Pulling all images " +
      "can take a few minutes; pass `languages` to pull only what the tool needs.",
    inputSchema: {
      languages: z
        .array(z.enum(["python", "node", "go", "ruby"]))
        .optional()
        .describe("Sandbox images to pull. Default: all four."),
      pull_images: z.boolean().optional().describe("Pull the sandbox images when Docker is running. Default true."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ languages, pull_images }) => {
    const done = [];
    let bin;
    try {
      bin = await ensureProbe();
      done.push(`Probe binary ready: ${probeVersion(bin)} at \`${bin}\``);
    } catch (err) {
      return textResult(`Could not install the Probe binary: ${err.message}`, true);
    }

    let setup = checkSetup();
    if (setup.docker.daemon && pull_images !== false) {
      for (const lang of languages ?? Object.keys(SANDBOX_IMAGES)) {
        const image = SANDBOX_IMAGES[lang];
        if (setup.images[image]) {
          done.push(`${image} already pulled`);
          continue;
        }
        log(`pulling ${image}...`);
        const r = spawnSync("docker", ["pull", image], { encoding: "utf8", timeout: PULL_TIMEOUT_MS, windowsHide: true });
        done.push(r.status === 0 ? `Pulled ${image}` : `Could not pull ${image}: ${stripAnsi(r.stderr || r.error?.message || "").trim()}`);
      }
      setup = checkSetup();
    }

    const left = nextSteps(setup);
    return textResult(
      [
        "## Probe install",
        "",
        ...done.map((d) => `- ${d}`),
        "",
        setupTable(setup),
        "",
        sandboxLine(setup),
        "",
        "### Still to do",
        left.length ? stepsList(left) : "Nothing. Probe is fully set up.",
        ...(left.some((st) => st.who === "you")
          ? ["", "Steps for you install or start system software. Show them to the user and run them only with their permission."]
          : []),
      ].join("\n")
    );
  }
);

server.registerTool(
  "probe_scan",
  {
    title: "Scan an agent tool with Probe",
    description:
      "Runs Trustabl Probe on a directory of agent tool code (Python, Go, JavaScript/TypeScript, Ruby, " +
      "Shell). Static analysis always runs; with sandbox 'auto' (default) the tool is also run in an " +
      "isolated, network-blocked sandbox when Docker or OpenShell is ready, which catches problems " +
      "that only show up at runtime. Returns a readiness score, the draft network allow list (an " +
      "OpenShell network policy), and findings worst-first, each with a fix hint for you to apply. " +
      "Writes network_policies.draft.yaml, probe.findings.json, probe.profile.json and " +
      "autofix-attestation.json into the scanned directory.",
    inputSchema: {
      path: z.string().optional().describe("Directory with the tool code. Defaults to the current directory."),
      entrypoints: z
        .array(z.string())
        .optional()
        .describe("Entry point files inside the directory, e.g. ['tool.py']. Default: Probe discovers them."),
      sandbox: z
        .enum(["auto", "on", "off"])
        .optional()
        .describe("'auto' (default) uses the sandbox when a runner is ready; 'on' fails without one; 'off' is static only."),
      allow_write_tools: z
        .boolean()
        .optional()
        .describe(
          "Run tools that look destructive (network writes, deletes, payments) in the sandbox too. " +
            "Default false: they are skipped and only analyzed statically. Only set true when the user asks."
        ),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ path: target, entrypoints, sandbox = "auto", allow_write_tools }) => {
    const dir = path.resolve(target || process.cwd());
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) return textResult(`Not a directory: ${dir}`, true);

    let bin;
    try {
      bin = await ensureProbe();
    } catch (err) {
      return textResult(`Could not install the Probe binary: ${err.message}\nRun probe_check_setup for details.`, true);
    }

    let runner = null;
    if (sandbox !== "off") {
      const setup = checkSetup();
      runner = setup.sandbox.runner;
      if (!runner && sandbox === "on") {
        return textResult(
          `No sandbox runner is ready.\n\n${sandboxLine(setup)}\n\n### Next steps\n${stepsList(nextSteps(setup))}`,
          true
        );
      }
    }

    const args = ["fix", "--source", dir, "--no-sign", "--output", "json"];
    for (const ep of entrypoints ?? []) args.push("--entrypoint", ep);
    if (runner) args.push("--sandbox", "--runner", runner);
    if (allow_write_tools) args.push("--allow-write-tools");

    log(`running ${path.basename(bin)} ${args.join(" ")}`);
    const r = spawnSync(bin, args, {
      encoding: "utf8",
      timeout: SCAN_TIMEOUT_MS,
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
    });
    const stderr = stripAnsi(r.stderr ?? "");
    if (r.error) return textResult(`Probe did not finish: ${r.error.message}`, true);
    if (stderr.includes("--model is required")) {
      return textResult(
        `This Probe version (${probeVersion(bin)}) needs a model to run. Probe v0.2.3 and later ` +
          "run without one: set PROBE_VERSION to v0.2.3 or later, or PROBE_BIN to a local build.",
        true
      );
    }
    if (r.status !== 0) {
      const tail = stderr.trim().split("\n").slice(-30).join("\n");
      return textResult(`Probe failed on ${dir} (exit ${r.status}):\n\n\`\`\`\n${tail}\n\`\`\``, true);
    }

    const findingsFile = path.join(dir, "probe.findings.json");
    const attestationFile = path.join(dir, "autofix-attestation.json");
    const policyFile = path.join(dir, "network_policies.draft.yaml");
    const profileFile = path.join(dir, "probe.profile.json");
    const report = readJson(findingsFile);
    const attestation = readJson(attestationFile);
    const profile = readJson(profileFile);
    if (!report || !attestation) {
      return textResult(`Probe ran but did not write its reports to ${dir}.\n\n\`\`\`\n${stderr.trim().slice(-2000)}\n\`\`\``, true);
    }

    const findings = [...(report.findings ?? [])].sort(
      (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)
    );
    const returned = findings.slice(0, MAX_FINDINGS_RETURNED);
    const counts = findings.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] ?? 0) + 1 }), {});
    const allowList = (attestation.network_calls ?? []).map((e) => `${e.host}:${e.port}`);
    const sandboxRan = (profile?.tools ?? []).some((t) => t.harness_id);
    const notes = [
      ...new Set(
        stderr
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => /sandbox skipped|sandbox unavailable|warning:/i.test(l))
      ),
    ];
    const rel = (f) => (f ? (path.isAbsolute(f) ? path.relative(dir, f) : f) : "(whole run)");

    const sandboxState = !runner
      ? sandbox === "off"
        ? "off (static only)"
        : "not available (static only, see probe_check_setup)"
      : sandboxRan
        ? `ran with ${runner}`
        : `requested with ${runner}, but no tool ran in it (see the findings and notes)`;
    if (findings.some((f) => f.title?.startsWith("Sandbox execution skipped"))) {
      notes.push(
        "A tool that looks destructive was not run in the sandbox. To run it anyway, call probe_scan " +
          "with allow_write_tools: true, only if the user asks, ideally with staging credentials."
      );
    }

    const findingLines = returned.map((f, i) => {
      const ev = (f.evidence ?? [])
        .slice(0, MAX_EVIDENCE_PER_FINDING)
        .map((e) => `   - Evidence [${e.source}]: ${clip(`${e.label ? `${e.label}: ` : ""}${e.detail ?? ""}`, MAX_EVIDENCE_CHARS)}`);
      return [
        `${i + 1}. **${f.severity}** · ${f.title} · \`${rel(f.file)}\``,
        f.fix_hint ? `   - Fix: ${f.fix_hint.trim().replace(/\n/g, "\n     ")}` : null,
        ...ev,
      ]
        .filter(Boolean)
        .join("\n");
    });

    const summary = {
      scanned: dir,
      readiness_score: attestation.production_readiness_score,
      findings_total: findings.length,
      by_severity: counts,
      sandbox: sandboxState,
      allow_list: allowList,
      languages: attestation.languages_detected ?? [],
      findings_returned: returned.length,
      findings_truncated: findings.length - returned.length,
      files: { findings: findingsFile, policy: policyFile, profile: profileFile, attestation: attestationFile },
    };

    return textResult(
      [
        `## Probe scan: ${dir}`,
        "",
        `**Readiness ${attestation.production_readiness_score}/100** · ${findings.length} finding${findings.length === 1 ? "" : "s"}` +
          (findings.length ? ` (${Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(", ")})` : "") +
          ` · sandbox: ${sandboxState}`,
        "",
        "### Network allow list (draft)",
        allowList.length ? allowList.map((h) => `- ${h}`).join("\n") : "- (no outbound destinations found)",
        "",
        "Written as an unsigned OpenShell network policy draft: `network_policies.draft.yaml`.",
        "",
        `### Findings, worst first (${returned.length} of ${findings.length})`,
        findingLines.length ? findingLines.join("\n") : "None.",
        ...(notes.length ? ["", "### Notes", ...notes.map((n) => `- ${n}`)] : []),
        "",
        "Apply each fix hint yourself; Probe does not change the code. Every finding with full evidence is in `probe.findings.json`.",
        "",
        "### Details",
        "```json",
        JSON.stringify(summary, null, 2),
        "```",
      ].join("\n")
    );
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
log("MCP server ready");
