package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trustabl/agent-network-access-probe/internal/sandbox"
)

func sampleKeyInput() KeyInput {
	return KeyInput{
		Ext:          ".py",
		SourceHash:   HashSource([]byte("print('hi')")),
		Deps:         []string{"requests", "openai"},
		Runner:       "docker",
		BaseImage:    "python:3.11-slim",
		SandboxArgs:  "",
		FixturesHash: "",
		RulesVersion: RulesVersion,
	}
}

// TestKey_DeterministicAndDepOrderIndependent confirms identical KeyInputs
// hash identically regardless of Deps slice order.
func TestKey_DeterministicAndDepOrderIndependent(t *testing.T) {
	a := sampleKeyInput()
	b := sampleKeyInput()
	b.Deps = []string{"openai", "requests"} // reversed

	ka, kb := Key(a), Key(b)
	if ka == "" {
		t.Fatal("Key returned empty string")
	}
	if ka != kb {
		t.Errorf("Key differs by dep order: %q vs %q", ka, kb)
	}
}

// TestKey_SensitiveToEachField confirms changing any single field changes
// the key — a cache key that ignored one of these would silently reuse a
// prior run's evidence for a genuinely different config.
func TestKey_SensitiveToEachField(t *testing.T) {
	base := sampleKeyInput()
	baseKey := Key(base)

	variants := map[string]KeyInput{
		"ext":          setExt(base, ".js"),
		"source_hash":  setSourceHash(base, HashSource([]byte("different"))),
		"deps":         setDeps(base, []string{"requests"}),
		"runner":       setRunner(base, "openshell"),
		"base_image":   setBaseImage(base, "node:20"),
		"sandbox_args": setSandboxArgs(base, "--city=Manila"),
		"fixtures":     setFixturesHash(base, HashFixtures(map[string]string{"K": "V"})),
		"rules":        setRulesVersion(base, "2"),
	}

	for name, variant := range variants {
		if Key(variant) == baseKey {
			t.Errorf("changing %s did not change the key", name)
		}
	}
}

func setExt(k KeyInput, v string) KeyInput          { k.Ext = v; return k }
func setSourceHash(k KeyInput, v string) KeyInput   { k.SourceHash = v; return k }
func setDeps(k KeyInput, v []string) KeyInput       { k.Deps = v; return k }
func setRunner(k KeyInput, v string) KeyInput       { k.Runner = v; return k }
func setBaseImage(k KeyInput, v string) KeyInput    { k.BaseImage = v; return k }
func setSandboxArgs(k KeyInput, v string) KeyInput  { k.SandboxArgs = v; return k }
func setFixturesHash(k KeyInput, v string) KeyInput { k.FixturesHash = v; return k }
func setRulesVersion(k KeyInput, v string) KeyInput { k.RulesVersion = v; return k }

// TestLoadSave_RoundTrip confirms a saved ScanResult comes back identical.
func TestLoadSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := Key(sampleKeyInput())
	want := &sandbox.ScanResult{
		SandboxID:  "autofix-123",
		Candidates: []sandbox.Candidate{{Title: "Unbounded tool output", Severity: "warning"}},
		Logs:       "some logs",
		DurationMs: 500,
	}

	if err := Save(dir, key, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok := Load(dir, key)
	if !ok {
		t.Fatal("Load: ok = false, want true after Save")
	}
	if got.SandboxID != want.SandboxID || got.Logs != want.Logs || got.DurationMs != want.DurationMs {
		t.Errorf("Load round-trip mismatch: got %+v, want %+v", got, want)
	}
	if len(got.Candidates) != 1 || got.Candidates[0].Title != "Unbounded tool output" {
		t.Errorf("Load round-trip lost Candidates: %+v", got.Candidates)
	}
}

// TestLoad_MissingFileFailsOpen confirms a missing cache entry is a clean
// miss, never an error a caller has to handle specially.
func TestLoad_MissingFileFailsOpen(t *testing.T) {
	dir := t.TempDir()
	if _, ok := Load(dir, "does-not-exist"); ok {
		t.Error("Load: ok = true for a nonexistent key, want false")
	}
}

// TestLoad_CorruptFileFailsOpen confirms a corrupt cache file is treated as
// a miss rather than propagating a parse error — caching must never block a
// scan.
func TestLoad_CorruptFileFailsOpen(t *testing.T) {
	dir := t.TempDir()
	key := "corrupt"
	if err := os.WriteFile(filepath.Join(dir, key+".json"), []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("write corrupt cache file: %v", err)
	}
	if _, ok := Load(dir, key); ok {
		t.Error("Load: ok = true for a corrupt cache file, want false")
	}
}

// TestHashFixtures_NeverLeaksRawValues confirms the hash output never
// contains the raw fixture values as a substring — a coarse guard that the
// function returns a hash, not an encoding of the input.
func TestHashFixtures_NeverLeaksRawValues(t *testing.T) {
	secretValue := "sk-super-secret-value-12345"
	h := HashFixtures(map[string]string{"STRIPE_API_KEY": secretValue})
	if h == "" {
		t.Fatal("HashFixtures returned empty for a non-empty map")
	}
	if strings.Contains(h, secretValue) {
		t.Error("HashFixtures output contains the raw secret value")
	}
}

func TestHashFixtures_EmptyForEmptyMap(t *testing.T) {
	if h := HashFixtures(nil); h != "" {
		t.Errorf("HashFixtures(nil) = %q, want empty", h)
	}
	if h := HashFixtures(map[string]string{}); h != "" {
		t.Errorf("HashFixtures(empty map) = %q, want empty", h)
	}
}
