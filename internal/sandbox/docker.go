package sandbox

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// dockerScanTimeout bounds how long a scanned tool may run inside the
// network-isolated container before autofix gives up and stops it — mirrors
// the OpenShell path's execTimeout so a hanging tool can't hang `autofix fix`
// forever.
const dockerScanTimeout = 30 * time.Second

// volumeCreateMu serializes Docker volume creation across concurrent RunDocker calls.
// Volume names are content-addressed (dep hash), so two concurrent calls with the same
// dep set would otherwise race to create the same volume.
var volumeCreateMu sync.Mutex

// MultiLangImage is the Trustabl sandbox image with Go, Python, Node, and Ruby pre-installed.
// Used when scanning a repository with mixed language tools.
const MultiLangImage = "trustabl/sandbox:latest"

// dockerBaseImage returns the Docker Hub image to use for the given entrypoint.
// Falls back to per-language slim images when the multi-lang image is not needed.
func dockerBaseImage(entrypoint string) string {
	switch filepath.Ext(entrypoint) {
	case ".go":
		return "golang:1.25-alpine"
	case ".js", ".ts":
		return "node:20-slim"
	case ".rb":
		return "ruby:3-slim"
	default:
		return "python:3-slim"
	}
}

// RunDocker runs the tool inside a Docker container with network isolation.
//
// Two-phase approach:
//  1. Setup container (network enabled): pip-installs deps into a named volume.
//  2. Scan container (--network none):   runs the tool with the volume mounted.
//
// This avoids baking packages into the image — deps are installed on demand for
// the exact platform, and network access is removed before the tool executes.
// fixtures is merged into the sandbox environment on top of the hardcoded
// dummy defaults — see envPrefix.
func RunDocker(toolPath, entrypoint, baseImage, sandboxArgs, _ string, deps []string, fixtures map[string]string) (*ScanResult, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker not found on PATH — install Docker Desktop or Docker Engine")
	}
	if out, err := output("docker", "info"); err != nil {
		return nil, fmt.Errorf("docker daemon unavailable: %w\n%s", err, out)
	}

	if baseImage == "" {
		baseImage = dockerBaseImage(entrypoint)
	}

	// If the image isn't cached locally, pull it explicitly so the user sees
	// a status line instead of a silent hang.
	if _, err := output("docker", "image", "inspect", baseImage); err != nil {
		fmt.Fprintf(os.Stderr, "  ⬇  Pulling image %s (first use — this may take a minute)...\n", baseImage)
		if pullOut, pullErr := output("docker", "pull", baseImage); pullErr != nil {
			return nil, fmt.Errorf("docker pull %s failed: %w\n%s", baseImage, pullErr, pullOut)
		}
		fmt.Fprintf(os.Stderr, "  ✓  Image ready\n")
	}

	start := time.Now()

	// Phase 1: install deps into a cached named volume.
	// Volume name is derived from the sorted dep list so the same set of deps
	// always reuses the same volume — skipping the network install on subsequent runs.
	volName := ""
	if len(deps) > 0 {
		sorted := append([]string{}, deps...)
		sort.Strings(sorted)
		h := fnv.New32a()
		_, _ = fmt.Fprint(h, strings.Join(sorted, ","))
		volName = fmt.Sprintf("autofix-deps-%08x", h.Sum32())

		// Only run the setup container if the volume doesn't already exist.
		// Mutex prevents a race when multiple RunDocker calls share the same dep hash.
		volumeCreateMu.Lock()
		if _, err := output("docker", "volume", "inspect", volName); err != nil {
			installCmd := "pip install -q --target /site-packages " + strings.Join(deps, " ") + " 2>&1"
			if _, err := output("docker", "run", "--rm",
				"--name", volName+"-setup",
				"-v", volName+":/site-packages",
				baseImage, "/bin/sh", "-c", installCmd,
			); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: dep install failed: %v\n", err)
				volName = "" // don't mount a broken volume
			}
		}
		volumeCreateMu.Unlock()
		// Volume is intentionally kept after the run — cache for next invocation.
	}

	// Mount from the project root so local packages (e.g. examples/) are available
	// at /sandbox/tool alongside the tool. Entrypoint becomes relative to the root.
	projectRoot := FindProjectRoot(toolPath)
	absProject, _ := filepath.Abs(projectRoot)
	absEp, _ := filepath.Abs(filepath.Join(toolPath, entrypoint))
	relEp, err := filepath.Rel(absProject, absEp)
	if err != nil || relEp == "" {
		relEp = entrypoint
	}
	// execCmd below is a POSIX shell string run inside the Linux container —
	// a backslash-separated Windows path would have its separators stripped
	// by shell escaping, mangling the path (e.g. "a\b\c.py" -> "abc.py").
	relEp = filepath.ToSlash(relEp)

	// Phase 2: run the tool with --network none and the dep volume mounted read-only.
	containerName := fmt.Sprintf("autofix-%d", time.Now().UnixMilli())
	toolDir := "/sandbox/tool"
	execCmd := buildDockerExecCmd(toolDir, relEp, sandboxArgs, len(deps) > 0, fixtures)

	scanArgs := []string{
		"run", "--rm",
		"--name", containerName,
		"--network", "none",
		"--read-only",
		"--tmpfs", "/tmp:exec",
		"--memory", "256m",
		"--cpus", "0.5",
		"-v", projectRoot + ":/sandbox/tool:ro",
	}
	if len(deps) > 0 {
		scanArgs = append(scanArgs, "-v", volName+":/site-packages:ro")
	}
	scanArgs = append(scanArgs, baseImage, "/bin/sh", "-c", execCmd)

	ctx, cancel := context.WithTimeout(context.Background(), dockerScanTimeout)
	defer cancel()
	scanCmd := exec.CommandContext(ctx, "docker", scanArgs...)
	scanCmd.Cancel = func() error {
		// Killing the `docker run` client doesn't reliably stop the container
		// itself (it isn't run with -d, but it isn't attached to the client's
		// stdin/stdout in a way that guarantees the daemon tears it down) —
		// stop it explicitly by name before killing the client process.
		_ = exec.Command("docker", "stop", containerName).Run()
		return scanCmd.Process.Kill()
	}
	outBytes, _ := scanCmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("tool exec timed out after %s — container stopped", dockerScanTimeout)
	}
	out := ansi.ReplaceAllString(string(outBytes), "")
	candidates := ParseLogs(out)

	return &ScanResult{
		SandboxID:  containerName,
		Candidates: candidates,
		Logs:       out,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

// buildDockerExecCmd builds the shell command for Phase 2 (network-isolated) container.
// When hasDeps is true, /site-packages (the dep volume) is added to PYTHONPATH.
// fixtures merges with the hardcoded dummy env defaults (see envPrefix) and
// is applied to every language branch, not just Python.
func buildDockerExecCmd(toolDir, entrypoint, extraArgs string, hasDeps bool, fixtures map[string]string) string {
	cd := "cd " + toolDir + " && "
	tail := " 2>&1; exit 0"
	args := ""
	if extraArgs != "" {
		args = " " + extraArgs
	}
	env := envPrefix(fixtures)

	// /sandbox/tool allows local package imports; /site-packages has pip-installed deps.
	pythonPath := "PYTHONPATH=/sandbox/tool"
	if hasDeps {
		pythonPath += ":/site-packages"
	}
	pythonPath += " "

	switch filepath.Ext(entrypoint) {
	case ".py":
		// /sandbox/tool on PYTHONPATH lets local package imports resolve when
		// --source points at the package root (e.g. from examples.utils import ...).
		return cd + env + pythonPath + "PYTHONHASHSEED=0 python3 " + entrypoint + args + tail
	case ".go":
		goDir := filepath.Dir(entrypoint)
		return "cd " + toolDir + "/" + goDir + " && " + env + "GOWORK=off GOPATH=/tmp/go GOCACHE=/tmp/gocache go run ." + args + tail
	case ".js":
		return cd + env + "node " + entrypoint + args + tail
	case ".ts":
		return cd + env + "npx ts-node " + entrypoint + args + tail
	case ".rb":
		return cd + env + "ruby " + entrypoint + args + tail
	case ".sh":
		return cd + env + "bash " + entrypoint + args + tail
	default:
		return cd + env + "./" + entrypoint + args + tail
	}
}
