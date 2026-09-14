package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinDenyList_Matches(t *testing.T) {
	d := BuiltinDenyList()
	cases := []struct {
		host string
		want bool
	}{
		{"169.254.169.254", true},          // cloud metadata IP
		{"metadata.google.internal", true}, // GCP metadata hostname
		{"169.254.1.1", true},              // arbitrary link-local IP
		{"fe80::1", true},                  // IPv6 link-local
		{"api.stripe.com", false},          // unrelated public host
		{"8.8.8.8", false},                 // unrelated public IP
	}
	for _, c := range cases {
		if got := d.Match(c.host); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestDenyList_MatchIsCaseInsensitiveAndTrimsFQDNDot(t *testing.T) {
	d := NewDenyList()
	d.AddHost("Metadata.Google.Internal")
	if !d.Match("metadata.google.internal.") {
		t.Error("Match should be case-insensitive and tolerate a trailing FQDN dot")
	}
}

func TestDenyList_NilIsSafe(t *testing.T) {
	var d *DenyList
	if d.Match("169.254.169.254") {
		t.Error("nil DenyList should never match")
	}
}

func TestLoadDenyList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny.txt")
	content := `# comment line, should be skipped

api.evil-corp.example.com
10.0.0.0/8
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDenyList(path)
	if err != nil {
		t.Fatalf("LoadDenyList() error = %v", err)
	}
	if !d.Match("api.evil-corp.example.com") {
		t.Error("expected host entry to be loaded and matchable")
	}
	if !d.Match("10.1.2.3") {
		t.Error("expected CIDR entry to be loaded and matchable")
	}
	if d.Match("api.stripe.com") {
		t.Error("unrelated host should not match")
	}
}

func TestLoadDenyList_MalformedCIDRIsHardError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(path, []byte("not-a-cidr/nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDenyList(path); err == nil {
		t.Fatal("expected error for malformed CIDR line, got nil")
	}
}

func TestLoadDenyList_MissingFile(t *testing.T) {
	if _, err := LoadDenyList(filepath.Join(t.TempDir(), "does-not-exist.txt")); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestMerge(t *testing.T) {
	a := NewDenyList()
	a.AddHost("host-a.example.com")
	b := NewDenyList()
	b.AddHost("host-b.example.com")
	_ = b.AddCIDR("172.16.0.0/12")

	merged := Merge(a, b, BuiltinDenyList())

	for _, host := range []string{"host-a.example.com", "host-b.example.com", "169.254.169.254"} {
		if !merged.Match(host) {
			t.Errorf("merged list should match %q", host)
		}
	}
	if !merged.Match("172.20.0.1") {
		t.Error("merged list should match an IP inside the merged CIDR")
	}
}
