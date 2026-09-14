package class

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_Valid(t *testing.T) {
	dir := t.TempDir()
	toolA := filepath.Join(dir, "tool-a")
	toolB := filepath.Join(dir, "tool-b")
	if err := os.MkdirAll(toolA, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(toolB, 0o755); err != nil {
		t.Fatal(err)
	}

	classPath := filepath.Join(dir, "billing.yaml")
	writeFile(t, classPath, `
class: billing
tools:
  - path: `+toolA+`
  - path: `+toolB+`
    entrypoint: run.sh
`)

	c, err := Load(classPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.Name != "billing" {
		t.Errorf("Name = %q, want %q", c.Name, "billing")
	}
	if len(c.Tools) != 2 {
		t.Fatalf("len(Tools) = %d, want 2", len(c.Tools))
	}
	if c.Tools[1].Entrypoint != "run.sh" {
		t.Errorf("Tools[1].Entrypoint = %q, want %q", c.Tools[1].Entrypoint, "run.sh")
	}
}

func TestLoad_MissingName(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool-a")
	if err := os.MkdirAll(tool, 0o755); err != nil {
		t.Fatal(err)
	}
	classPath := filepath.Join(dir, "class.yaml")
	writeFile(t, classPath, `
tools:
  - path: `+tool+`
`)
	if _, err := Load(classPath); err == nil {
		t.Fatal("expected error for missing class name, got nil")
	}
}

func TestLoad_EmptyTools(t *testing.T) {
	dir := t.TempDir()
	classPath := filepath.Join(dir, "class.yaml")
	writeFile(t, classPath, `class: billing
tools: []
`)
	if _, err := Load(classPath); err == nil {
		t.Fatal("expected error for empty tools, got nil")
	}
}

func TestLoad_MissingPath(t *testing.T) {
	dir := t.TempDir()
	classPath := filepath.Join(dir, "class.yaml")
	writeFile(t, classPath, `class: billing
tools:
  - entrypoint: run.sh
`)
	if _, err := Load(classPath); err == nil {
		t.Fatal("expected error for tool missing path, got nil")
	}
}

func TestLoad_NonexistentPath(t *testing.T) {
	dir := t.TempDir()
	classPath := filepath.Join(dir, "class.yaml")
	writeFile(t, classPath, `class: billing
tools:
  - path: `+filepath.Join(dir, "does-not-exist")+`
`)
	if _, err := Load(classPath); err == nil {
		t.Fatal("expected error for nonexistent path, got nil")
	}
}

func TestLoad_DuplicateMember(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool-a")
	if err := os.MkdirAll(tool, 0o755); err != nil {
		t.Fatal(err)
	}
	classPath := filepath.Join(dir, "class.yaml")
	writeFile(t, classPath, `class: billing
tools:
  - path: `+tool+`
  - path: `+tool+`
`)
	if _, err := Load(classPath); err == nil {
		t.Fatal("expected error for duplicate member, got nil")
	}
}

func TestLoad_PathIsFileNotDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-dir.txt")
	writeFile(t, file, "hello")
	classPath := filepath.Join(dir, "class.yaml")
	writeFile(t, classPath, `class: billing
tools:
  - path: `+file+`
`)
	if _, err := Load(classPath); err == nil {
		t.Fatal("expected error for path that is a file, got nil")
	}
}
