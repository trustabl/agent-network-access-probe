package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowList_ExactHostMatch(t *testing.T) {
	a := NewAllowList()
	a.AddHost("api.stripe.com", SourceDeclared)

	src, matched := a.Match("api.stripe.com")
	if !matched || src != SourceDeclared {
		t.Errorf("Match() = (%q, %v), want (declared, true)", src, matched)
	}
	if _, matched := a.Match("api.evil.com"); matched {
		t.Error("unrelated host should not match")
	}
}

func TestAllowList_WildcardSuffixMatch(t *testing.T) {
	a := NewAllowList()
	a.AddWildcardSuffix("*.internal-orders.acme.com", SourcePlatform)

	src, matched := a.Match("orders.internal-orders.acme.com")
	if !matched || src != SourcePlatform {
		t.Errorf("Match() = (%q, %v), want (platform, true)", src, matched)
	}
	if _, matched := a.Match("acme.com"); matched {
		t.Error("bare parent domain should not match a wildcard suffix entry")
	}
}

func TestAllowList_CIDRMatch(t *testing.T) {
	a := NewAllowList()
	if err := a.AddCIDR("10.0.0.0/8", SourceDeclared); err != nil {
		t.Fatal(err)
	}
	src, matched := a.Match("10.1.2.3")
	if !matched || src != SourceDeclared {
		t.Errorf("Match() = (%q, %v), want (declared, true)", src, matched)
	}
	if _, matched := a.Match("8.8.8.8"); matched {
		t.Error("unrelated IP should not match")
	}
}

func TestAllowList_NilIsSafe(t *testing.T) {
	var a *AllowList
	if _, matched := a.Match("api.stripe.com"); matched {
		t.Error("nil AllowList should never match")
	}
	if entries := a.BroadEntries(); entries != nil {
		t.Errorf("BroadEntries() on nil = %v, want nil", entries)
	}
}

func TestAllowList_BroadEntries(t *testing.T) {
	a := NewAllowList()
	a.AddWildcardSuffix("*", SourceDeclared)               // bare wildcard
	a.AddWildcardSuffix("*.amazonaws.com", SourceDeclared) // spec's own example
	a.AddWildcardSuffix("*.internal-orders.acme.com", SourceDeclared)
	_ = a.AddCIDR("0.0.0.0/0", SourceDeclared)
	_ = a.AddCIDR("10.0.0.0/8", SourceDeclared)

	broad := a.BroadEntries()
	wantBroad := map[string]bool{
		"*":               true,
		"*.amazonaws.com": true,
		"0.0.0.0/0":       true,
	}
	got := map[string]bool{}
	for _, b := range broad {
		got[b] = true
	}
	for want := range wantBroad {
		if !got[want] {
			t.Errorf("BroadEntries() missing %q, got %v", want, broad)
		}
	}
	for _, notWant := range []string{"*.internal-orders.acme.com", "10.0.0.0/8"} {
		if got[notWant] {
			t.Errorf("BroadEntries() incorrectly flagged %q as broad", notWant)
		}
	}
}

func TestLoadAllowList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	content := `# comment line, should be skipped

api.stripe.com
*.internal-orders.acme.com
10.0.0.0/8
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAllowList(path, SourceDeclared)
	if err != nil {
		t.Fatalf("LoadAllowList() error = %v", err)
	}
	for _, host := range []string{"api.stripe.com", "orders.internal-orders.acme.com", "10.1.2.3"} {
		if _, matched := a.Match(host); !matched {
			t.Errorf("expected %q to match", host)
		}
	}
	if _, matched := a.Match("api.evil.com"); matched {
		t.Error("unrelated host should not match")
	}
}

func TestLoadAllowList_MalformedCIDRIsHardError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(path, []byte("not-a-cidr/nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAllowList(path, SourceDeclared); err == nil {
		t.Fatal("expected error for malformed CIDR line, got nil")
	}
}

func TestLoadAllowList_MissingFile(t *testing.T) {
	if _, err := LoadAllowList(filepath.Join(t.TempDir(), "does-not-exist.txt"), SourceDeclared); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestMergeAllow(t *testing.T) {
	declared := NewAllowList()
	declared.AddHost("api.stripe.com", SourceDeclared)
	platform := NewAllowList()
	platform.AddHost("nim.internal.example.com", SourcePlatform)

	merged := MergeAllow(declared, platform)

	if src, matched := merged.Match("api.stripe.com"); !matched || src != SourceDeclared {
		t.Errorf("merged Match(api.stripe.com) = (%q, %v), want (declared, true)", src, matched)
	}
	if src, matched := merged.Match("nim.internal.example.com"); !matched || src != SourcePlatform {
		t.Errorf("merged Match(nim.internal.example.com) = (%q, %v), want (platform, true)", src, matched)
	}
}
