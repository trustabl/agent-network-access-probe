// Package cache provides an optional, per-tool result cache so identical
// scans (same tool content, same effective run configuration) can reuse a
// prior sandbox run's evidence instead of re-executing it. Deliberately not
// keyed on the tool's filesystem path — see KeyInput's doc comment — so the
// same tool referenced by two different agent classes shares one entry
// ("cross-agent reuse", per the product roadmap's Slice 8 done-condition).
package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/trustabl/agent-network-access-probe/internal/sandbox"
)

// RulesVersion is bumped by hand whenever analyzer rule behavior changes in
// a way that should invalidate previously-cached results. No automated
// rules-versioning scheme exists yet — this is the same hardcoded-string
// idiom already used for SchemaVersion elsewhere in this codebase (profile,
// attestation, findings).
const RulesVersion = "1"

// KeyInput is every input that determines whether two scans should be
// considered "the same tool run" for cache purposes. Deliberately excludes
// the tool's filesystem path/directory: the same tool content scanned from
// two different locations (e.g. vendored into two different agent classes)
// should share one cache entry, not be treated as unrelated. Two tools with
// byte-identical source and identical effective config produce the same
// egress evidence — that's the premise of content-addressed caching.
type KeyInput struct {
	Ext          string   // filepath.Ext(entrypoint)
	SourceHash   string   // sha256 hex of the entrypoint's source bytes
	Deps         []string // resolved dependency list (sorted before hashing)
	Runner       string   // "docker" | "openshell"
	BaseImage    string   // fully resolved image string
	SandboxArgs  string
	FixturesHash string // sha256 hex of the loaded env-fixtures map, "" if none
	RulesVersion string
}

// Key returns a deterministic hex-encoded sha256 identifying in. Deps is
// sorted internally so member order never changes the key.
func Key(in KeyInput) string {
	sorted := append([]string{}, in.Deps...)
	sort.Strings(sorted)
	in.Deps = sorted
	data, err := json.Marshal(in)
	if err != nil {
		// json.Marshal on a plain struct of strings/slices cannot fail in
		// practice; treat as unreachable rather than propagate an error
		// through every call site for a case that can't happen.
		return ""
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// HashSource returns a hex-encoded sha256 of src.
func HashSource(src []byte) string {
	sum := sha256.Sum256(src)
	return fmt.Sprintf("%x", sum)
}

// HashFixtures returns a deterministic hex-encoded sha256 over fixtures'
// key=value pairs, sorted by key. Empty for a nil/empty map. Only the hash
// is ever used or stored anywhere — raw fixture values never touch a cache
// key or a cache entry on disk.
func HashFixtures(fixtures map[string]string) string {
	if len(fixtures) == 0 {
		return ""
	}
	keys := make([]string, 0, len(fixtures))
	for k := range fixtures {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{'='})
		h.Write([]byte(fixtures[k]))
		h.Write([]byte{'\n'})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Dir resolves and creates the default cache directory.
func Dir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache dir: %w", err)
	}
	dir := filepath.Join(base, "trustabl-probe", "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}
	return dir, nil
}

// entry is the on-disk envelope for one cache file.
type entry struct {
	Key      string              `json:"key"`
	CachedAt string              `json:"cached_at"`
	Result   *sandbox.ScanResult `json:"result"`
}

// Load returns the cached ScanResult for key, and whether it was found. Any
// read or parse error is treated as a miss — caching is a pure optimization
// and must never block or fail a scan.
func Load(dir, key string) (*sandbox.ScanResult, bool) {
	data, err := os.ReadFile(filepath.Join(dir, key+".json"))
	if err != nil {
		return nil, false
	}
	var e entry
	if err := json.Unmarshal(data, &e); err != nil || e.Result == nil {
		return nil, false
	}
	return e.Result, true
}

// Save writes result under key, atomically (temp file + rename) so a
// concurrent reader never observes a partially-written cache file.
func Save(dir, key string, result *sandbox.ScanResult) error {
	e := entry{
		Key:      key,
		CachedAt: time.Now().UTC().Format(time.RFC3339),
		Result:   result,
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	dest := filepath.Join(dir, key+".json")
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}
