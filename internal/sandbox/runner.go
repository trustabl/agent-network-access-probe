package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ScanResult struct {
	SandboxID  string      `json:"sandbox_id"`
	Candidates []Candidate `json:"candidates"`
	Logs       string      `json:"logs"`
	DurationMs int64       `json:"duration_ms"`
}

// policyYAML is the sandbox policy every OpenShell run is created with.
// network_policies.outbound is an explicit empty list — not an empty/absent
// map — so the intent is unambiguous: nothing is allowed. This repo has no
// openshell binary or docs available to confirm how the daemon treats an
// empty/unspecified network_policies block, so this is a defensive choice,
// not a verified one; live confirmation against a real OpenShell install is
// still needed before relying on this for a production-facing guarantee.
// Docker's --network none (docker.go) is the one runner with an OS-level,
// in-repo-verifiable network guarantee.
const policyYAML = `version: 1

filesystem_policy:
  read_only: [/usr, /lib, /etc, /dev/urandom, /dev/random]
  read_write: [/sandbox, /tmp]

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  outbound: []
`

// execTimeout is the max seconds a tool is allowed to run inside the sandbox.
const execTimeout = "30"

// DefaultBaseImage returns the recommended OpenShell base image.
// openclaw is the standard NVIDIA community sandbox — it has the required
// sandbox user and network namespace support pre-configured.
func DefaultBaseImage(entrypoint string) string {
	return "openclaw"
}

// Run executes the tool inside an OpenShell sandbox and returns a ScanResult.
//
// Lifecycle:
//  1. create  — provisions the sandbox from the base image (no foreground command)
//  2. upload  — copies the tool directory into /sandbox/tool
//  3. exec    — runs the tool with a 30-second timeout; policy violations appear in logs
//  4. delete  — always runs via defer, even on error
//
// deps is an optional list of pip package names to install before running the tool.
// The Python version is detected from inside the sandbox so the correct binary wheels
// are downloaded. Pass nil to skip.
// SandboxHandle is a running sandbox that can execute multiple tools.
// Call Close() when done to delete the sandbox.
type SandboxHandle struct {
	ID             string
	policyPath     string
	createCmd      *exec.Cmd
	depsInstallCmd string // pre-built pip install prefix (set after first dep upload)
}

// OpenSandbox creates a new sandbox and waits for it to be ready.
// Returns a SandboxHandle; caller must call Close() to clean up.
func OpenSandbox(baseImage string) (*SandboxHandle, error) {
	if _, err := output("openshell", "sandbox", "list"); err != nil {
		return nil, fmt.Errorf("openshell gateway unavailable (run 'openshell gateway start'): %w", err)
	}
	policyPath, err := writeTempPolicy(policyYAML)
	if err != nil {
		return nil, fmt.Errorf("write policy: %w", err)
	}
	id := fmt.Sprintf("autofix-%d", time.Now().UnixMilli())
	createCmd := exec.Command("openshell", "sandbox", "create",
		"--name", id,
		"--from", baseImage,
		"--policy", policyPath,
		"--", "sleep", "infinity",
	)
	if err := createCmd.Start(); err != nil {
		return nil, fmt.Errorf("sandbox create: %w", err)
	}
	if err := waitForReady(id, 3*time.Minute); err != nil {
		_ = createCmd.Process.Kill()
		return nil, fmt.Errorf("sandbox not ready: %w", err)
	}
	return &SandboxHandle{ID: id, policyPath: policyPath, createCmd: createCmd}, nil
}

// UploadDeps detects the Python version, downloads matching wheels, uploads and
// prepares the install prefix. Safe to call once and reuse across Exec calls.
func (h *SandboxHandle) UploadDeps(deps []string) {
	if len(deps) == 0 {
		return
	}
	pyVer := detectPythonVersion(h.ID)
	depsDir, err := downloadDeps(deps, pyVer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: dep download failed: %v\n", err)
		return
	}
	defer os.RemoveAll(depsDir)
	wheelsRemote := "/tmp/" + filepath.Base(depsDir)
	if err := run("openshell", "sandbox", "upload", h.ID, depsDir, "/tmp"); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: dep upload failed: %v\n", err)
		return
	}
	h.depsInstallCmd = "PYTHONHASHSEED=0 pip install -q --no-index --find-links " + wheelsRemote +
		" --target /tmp/site-packages " + wheelsRemote + "/*.whl 2>&1 || true; "
}

// Upload copies the tool directory into the sandbox. Call once before Exec.
func (h *SandboxHandle) Upload(toolPath string) error {
	return run("openshell", "sandbox", "upload", h.ID, toolPath, "/sandbox/tool")
}

// Exec runs a single tool inside the sandbox and returns scan results.
// Call Upload first to make the tool files available. fixtures is merged
// into the sandbox environment on top of the hardcoded dummy defaults — see
// envPrefix.
func (h *SandboxHandle) Exec(toolPath, entrypoint, sandboxArgs string, fixtures map[string]string) (*ScanResult, error) {
	start := time.Now()
	toolDir := "/sandbox/tool/" + filepath.Base(toolPath)
	pyPath := toolDir
	if h.depsInstallCmd != "" {
		pyPath = "/tmp/site-packages:" + toolDir
	}
	shellCmd := buildExecCmd(entrypoint, sandboxArgs, pyPath, fixtures)
	if h.depsInstallCmd != "" {
		shellCmd = h.depsInstallCmd + shellCmd
	}
	toolOut, _ := output("openshell", "sandbox", "exec",
		"-n", h.ID,
		"--workdir", toolDir,
		"--timeout", execTimeout,
		"--no-tty",
		"--", "/bin/sh", "-c", shellCmd,
	)
	policyLogs := collectSandboxPolicyLogs(h.ID)
	rawLogs, _ := output("openshell", "logs", h.ID)
	toolOut = ansi.ReplaceAllString(toolOut, "")
	allLogs := ansi.ReplaceAllString(rawLogs, "") +
		"\n--- sandbox policy events ---\n" + policyLogs +
		"\n--- tool output ---\n" + toolOut
	return &ScanResult{
		SandboxID:  h.ID,
		Candidates: ParseLogs(allLogs),
		Logs:       allLogs,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

// Close deletes the sandbox, removes the temp policy file, and kills the background process.
func (h *SandboxHandle) Close() {
	_ = run("openshell", "sandbox", "delete", h.ID)
	if h.policyPath != "" {
		_ = os.Remove(h.policyPath)
	}
	_ = h.createCmd.Process.Kill()
}

// Run is the single-tool convenience wrapper (existing behaviour unchanged).
func Run(toolPath, entrypoint, baseImage, sandboxArgs string, deps []string, fixtures map[string]string) (*ScanResult, error) {
	h, err := OpenSandbox(baseImage)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	h.UploadDeps(deps)
	if err := h.Upload(toolPath); err != nil {
		return nil, fmt.Errorf("sandbox upload: %w", err)
	}
	return h.Exec(toolPath, entrypoint, sandboxArgs, fixtures)
}

// dummyEnvDefaults are placeholder values for common API key env vars so
// agent tools can load and reach their network calls inside the sandbox
// without crashing at import time due to missing credentials. User-supplied
// fixtures (see LoadEnvFixtures) override these on key collision — e.g. a
// tool's real payment-provider credential name isn't covered by this fixed
// list, so a caller can supply it via --env-fixtures instead.
var dummyEnvDefaults = map[string]string{
	"OPENAI_API_KEY":        "sk-dummy",
	"ANTHROPIC_API_KEY":     "sk-ant-dummy",
	"GOOGLE_API_KEY":        "dummy",
	"AWS_ACCESS_KEY_ID":     "dummy",
	"AWS_SECRET_ACCESS_KEY": "dummy",
	"HUGGINGFACE_API_KEY":   "dummy",
}

// envPrefix builds a "KEY=val KEY2=val2 " shell-exportable prefix from
// dummyEnvDefaults merged with any user-supplied fixtures (fixtures win on
// key collision). Applied uniformly across every language branch in
// buildExecCmd/buildDockerExecCmd — previously this was Python-only.
func envPrefix(fixtures map[string]string) string {
	merged := make(map[string]string, len(dummyEnvDefaults)+len(fixtures))
	for k, v := range dummyEnvDefaults {
		merged[k] = v
	}
	for k, v := range fixtures {
		merged[k] = v
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic shell command across runs
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(shellQuoteSingle(merged[k]))
		b.WriteByte(' ')
	}
	return b.String()
}

// shellQuoteSingle wraps s in single quotes for safe use as one POSIX shell
// word, escaping any embedded single quote using the standard POSIX technique.
func shellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// FindProjectRoot walks up from dir until it finds a project root marker
// (.git, requirements.txt, pyproject.toml, setup.py). Returns the absolute
// path of the root, or the absolute path of dir as a fallback.
func FindProjectRoot(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	cur := abs
	for {
		for _, marker := range []string{".git", "requirements.txt", "pyproject.toml", "setup.py"} {
			if _, err := os.Stat(filepath.Join(cur, marker)); err == nil {
				return cur
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs
		}
		cur = parent
	}
}

// buildExecCmd returns the shell command to run the tool.
// --workdir is set by the caller so no cd prefix is needed.
// pythonPath is set as PYTHONPATH; it should equal the sandbox directory that
// was uploaded so local packages are importable from the correct root.
// fixtures merges with the hardcoded dummy env defaults (see envPrefix) and
// is applied to every language branch, not just Python.
func buildExecCmd(entrypoint, extraArgs, pythonPath string, fixtures map[string]string) string {
	tail := " 2>&1; exit 0"
	args := ""
	if extraArgs != "" {
		args = " " + extraArgs
	}
	env := envPrefix(fixtures)
	switch filepath.Ext(entrypoint) {
	case ".py":
		return env + "PYTHONPATH=" + pythonPath + " PYTHONHASHSEED=0 python3 " + entrypoint + args + tail
	case ".go":
		return env + "GOPATH=/tmp/go GOCACHE=/tmp/gocache go run *.go" + args + tail
	case ".js":
		return env + "node " + entrypoint + args + tail
	case ".ts":
		return env + "npx ts-node " + entrypoint + args + tail
	case ".rb":
		return env + "ruby " + entrypoint + args + tail
	case ".sh":
		return env + "bash " + entrypoint + args + tail
	default:
		return env + "./" + entrypoint + args + tail
	}
}

func waitForReady(sandboxID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	dot := time.NewTicker(5 * time.Second)
	defer dot.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-tick.C:
			out, _ := output("openshell", "sandbox", "list")
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, sandboxID) && strings.Contains(line, "Ready") {
					fmt.Println()
					return nil
				}
			}
		case <-dot.C:
			fmt.Print(".")
		}
	}
	fmt.Println()
	return fmt.Errorf("timed out waiting for sandbox %s to be ready", sandboxID)
}

func collectSandboxPolicyLogs(sandboxID string) string {
	out, _ := output("openshell", "logs", sandboxID, "--source", "sandbox", "-n", "1000")
	return ansi.ReplaceAllString(out, "")
}

// detectPythonVersion runs a quick exec in a ready sandbox to find out which
// CPython minor version is installed (e.g. "312"). Used to download matching
// binary wheels. Falls back to "311" if the exec fails or produces no output.
func detectPythonVersion(sandboxID string) string {
	out, _ := output("openshell", "sandbox", "exec", "-n", sandboxID, "--no-tty", "--",
		"/bin/sh", "-c", "PYTHONHASHSEED=0 python3 -c 'import sys; print(str(sys.version_info.major)+str(sys.version_info.minor).zfill(2))'",
	)
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(ansi.ReplaceAllString(raw, ""))
		// Skip OpenShell infra lines; look for a 3-digit version string like "311".
		if len(line) == 3 && line[0] == '3' {
			return line
		}
	}
	return "311"
}

// downloadDeps downloads manylinux2014_x86_64 wheels for the given pip packages
// targeting the specified CPython version (e.g. "312") and returns the directory.
// The caller is responsible for removing the directory when done.
// hostPython returns the Python executable to use on the host for downloading
// wheels. Tries python3 first (Linux/macOS), falls back to python (Windows).
func hostPython() string {
	if _, err := exec.LookPath("python3"); err == nil {
		return "python3"
	}
	return "python"
}

func downloadDeps(deps []string, pyVer string) (string, error) {
	dir, err := os.MkdirTemp("", "autofix-deps-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	// --only-binary=:all: is required by pip when --platform or --python-version
	// is set. Pure-Python packages (openai, requests) publish universal .whl
	// files which satisfy this constraint. Cross-compile for manylinux2014_x86_64
	// so wheels are usable inside the Linux sandbox regardless of the host OS.
	args := []string{"-m", "pip", "download", "-q",
		"--dest", dir,
		"--only-binary=:all:",
		"--platform", "manylinux2014_x86_64",
		"--python-version", pyVer,
	}
	args = append(args, deps...)
	cmd := exec.Command(hostPython(), args...)
	cmd.Dir = dir // run from the temp dir so os.getcwd() is always valid
	out, err := cmd.CombinedOutput()
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return dir, nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func output(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
