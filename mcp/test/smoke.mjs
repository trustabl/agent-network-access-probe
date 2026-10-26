// Smoke test: start the bundled server over stdio the way an MCP client does,
// then call the tools. Exits non-zero on the first failure.
//
//   node test/smoke.mjs                  handshake, tools/list, probe_check_setup
//   SMOKE_SCAN=1 node test/smoke.mjs     also runs probe_scan on test/fixture with
//                                        the released Probe the server downloads
//   PROBE_BIN=<path> node test/smoke.mjs the same scan with a local Probe build
// The scan is static only, so it needs no Docker.

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const child = spawn(process.execPath, [path.join(root, "dist", "index.js")], { stdio: ["pipe", "pipe", "inherit"] });

let buf = "";
const waiting = new Map();
child.stdout.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (line) {
      const msg = JSON.parse(line);
      waiting.get(msg.id)?.(msg);
    }
  }
});

let nextId = 1;
function call(method, params, timeoutMs = 120000) {
  const id = nextId++;
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${method} timed out`)), timeoutMs);
    waiting.set(id, (msg) => {
      clearTimeout(t);
      if (msg.error) reject(new Error(JSON.stringify(msg.error)));
      else resolve(msg.result);
    });
  });
}

function check(cond, what) {
  if (!cond) {
    console.error(`FAIL: ${what}`);
    child.kill();
    process.exit(1);
  }
  console.log(`ok: ${what}`);
}

const init = await call("initialize", {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "smoke", version: "0" },
});
check(init.serverInfo?.name === "trustabl-agent-network-access-probe", "initialize");
child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);

const { tools } = await call("tools/list", {});
const names = tools.map((t) => t.name).sort().join(",");
check(names === "probe_check_setup,probe_install,probe_scan", `tools/list (${names})`);
check(tools.every((t) => t.title && "readOnlyHint" in (t.annotations ?? {})), "every tool has a title and readOnlyHint");

const setup = await call("tools/call", { name: "probe_check_setup", arguments: {} });
check(!setup.isError && setup.content[0].text.includes("| Probe binary |"), "probe_check_setup");

if (process.env.PROBE_BIN || process.env.SMOKE_SCAN) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "probe-smoke-"));
  fs.copyFileSync(path.join(root, "test", "fixture", "tool.py"), path.join(dir, "tool.py"));
  const scan = await call(
    "tools/call",
    { name: "probe_scan", arguments: { path: dir, entrypoints: ["tool.py"], sandbox: "off" } },
    300000
  );
  const text = scan.content[0].text;
  check(!scan.isError, `probe_scan finished${scan.isError ? `:\n${text}` : ""}`);
  check(text.includes("api.example.com:443"), "allow list has the URL from the code");
  check(text.includes("- Fix: "), "findings come with fix hints");
  fs.rmSync(dir, { recursive: true, force: true });
} else {
  console.log("skip: probe_scan (set SMOKE_SCAN=1, or PROBE_BIN to a local Probe build)");
}

child.kill();
console.log("smoke test passed");
