package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fix without --model must still scan and write every report, skip fix
// generation, and print an empty fix list in json mode. Static analysis only:
// no sandbox, no signing, no model, so the run needs no network.
func TestFixWithoutModelWritesReports(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the CLI")
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "demo", "refund-tool", "tool.py"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tool.py"), src, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "run", ".", "fix",
		"--source", dir, "--entrypoint", "tool.py", "--no-sign", "--output", "json")
	cmd.Env = append(os.Environ(), "OPENAI_API_KEY=", "ANTHROPIC_API_KEY=", "LLM_API_KEY=")
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("fix without --model failed: %v\n%s", err, stderr)
	}
	if got := strings.TrimSpace(string(out)); got != "[]" {
		t.Errorf("stdout = %q, want []", got)
	}
	for _, name := range []string{
		"network_policies.draft.yaml",
		"probe.profile.json",
		"probe.findings.json",
		"autofix-attestation.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
}
