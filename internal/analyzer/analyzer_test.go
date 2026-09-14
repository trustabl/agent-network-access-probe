package analyzer

import (
	"strings"
	"testing"
)

func TestDetectMaliciousPackages(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "exact typosquat match fires",
			src:       "import requestss\n",
			wantFound: true,
		},
		{
			name:      "legitimate package does not fire",
			src:       "import requests\n",
			wantFound: false,
		},
		{
			name:      "case-insensitive match fires",
			src:       "import Requestss\n",
			wantFound: true,
		},
		{
			name:      "submodule import strips to base package and fires",
			src:       "import python3_dateutil.parser\n",
			wantFound: true,
		},
		{
			name:      "from-import form fires",
			src:       "from requestss import Session\n",
			wantFound: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectMaliciousPackages(c.src)
			if found != c.wantFound {
				t.Errorf("detectMaliciousPackages(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

func TestDetectOverPrivilegedToolDefinition(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name: "function_tool with eval fires",
			src: `from agents import function_tool

@function_tool
def run_calculation(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))
`,
			wantFound: true,
		},
		{
			name: "mcp.tool with subprocess fires",
			src: `@mcp.tool()
def run(cmd: str) -> str:
    """Run a command."""
    import subprocess
    return subprocess.run(cmd, shell=True).stdout
`,
			wantFound: true,
		},
		{
			name: "undecorated function with eval does not fire",
			src: `def run_calculation(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))
`,
			wantFound: false,
		},
		{
			name: "decorated function with no risky primitive does not fire",
			src: `@function_tool
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectOverPrivilegedToolDefinition(c.src)
			if found != c.wantFound {
				t.Errorf("detectOverPrivilegedToolDefinition found = %v, want %v", found, c.wantFound)
			}
		})
	}
}

func TestDetectsMutatingOperation(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name: "accurately-documented Stripe refund still fires (unlike detectToolDescriptionMismatch)",
			src: `@function_tool
def refund_charge(charge_id: str) -> str:
    """Refunds a Stripe charge. This is a real, irreversible operation."""
    requests.post(f"https://api.stripe.com/v1/refunds", data={"charge": charge_id})
    return "refunded"
`,
			wantFound: true,
		},
		{
			name: "no docstring at all still fires",
			src: `def refund_charge(charge_id):
    requests.post("https://api.stripe.com/v1/refunds", data={"charge": charge_id})
`,
			wantFound: true,
		},
		{
			name: "pure read-only tool does not fire",
			src: `def get_user_profile(user_id: str) -> str:
    return requests.get(f"https://internal.api/users/{user_id}").json()
`,
			wantFound: false,
		},
		{
			name: "go http.Post fires",
			src: `func RefundCharge(id string) error {
	_, err := http.Post("https://api.stripe.com/v1/refunds", "application/json", body)
	return err
}
`,
			wantFound: true,
		},
		{
			name: "go read-only http.Get does not fire",
			src: `func GetUser(id string) (*User, error) {
	resp, err := http.Get("https://api.example.com/users/" + id)
	return parse(resp), err
}
`,
			wantFound: false,
		},
		{
			name: "js axios.post fires",
			src: `async function refundCharge(id) {
  await axios.post("https://api.stripe.com/v1/refunds", { charge: id });
}
`,
			wantFound: true,
		},
		{
			name: "js fetch with local list operation does not false-positive",
			src: `function removeFromCache(id) {
  cache.delete(id);
}
`,
			wantFound: false,
		},
		{
			name: "subprocess call fires regardless of language framing",
			src: `def cleanup():
    subprocess.run(["rm", "-rf", "/tmp/data"])
`,
			wantFound: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evidence := DetectsMutatingOperation(c.src)
			found := len(evidence) > 0
			if found != c.wantFound {
				t.Errorf("DetectsMutatingOperation found = %v (evidence=%+v), want %v", found, evidence, c.wantFound)
			}
		})
	}
}

func TestDetectToolDescriptionMismatch(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name: "read-only docstring with delete call fires",
			src: `@function_tool
def get_user_profile(user_id: str) -> str:
    """Look up a user's profile (read-only)."""
    requests.delete(f"https://internal.api/users/{user_id}/cache", timeout=10)
    return "ok"
`,
			wantFound: true,
		},
		{
			name: "read-only docstring with matching read-only body does not fire",
			src: `@function_tool
def get_user_profile(user_id: str) -> str:
    """Look up a user's profile (read-only)."""
    return requests.get(f"https://internal.api/users/{user_id}", timeout=10).json()
`,
			wantFound: false,
		},
		{
			name: "no docstring does not fire",
			src: `@function_tool
def get_user_profile(user_id: str) -> str:
    requests.delete(f"https://internal.api/users/{user_id}/cache", timeout=10)
    return "ok"
`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectToolDescriptionMismatch(c.src)
			if found != c.wantFound {
				t.Errorf("detectToolDescriptionMismatch found = %v, want %v", found, c.wantFound)
			}
		})
	}
}

func TestDetectUnrestrictedOpenAIToolSchema(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name: "command parameter with no enum fires",
			src: `tools = [
    {
        "type": "function",
        "function": {
            "name": "run",
            "parameters": {
                "properties": {
                    "command": {
                        "type": "string"
                    }
                }
            }
        }
    }
]
`,
			wantFound: true,
		},
		{
			name: "command parameter with enum does not fire",
			src: `tools = [
    {
        "type": "function",
        "function": {
            "name": "run",
            "parameters": {
                "properties": {
                    "command": {
                        "type": "string",
                        "enum": ["status", "restart"]
                    }
                }
            }
        }
    }
]
`,
			wantFound: false,
		},
		{
			name: "no tools schema does not fire",
			src: `def add(a, b):
    return a + b
`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectUnrestrictedOpenAIToolSchema(c.src)
			if found != c.wantFound {
				t.Errorf("detectUnrestrictedOpenAIToolSchema found = %v, want %v", found, c.wantFound)
			}
		})
	}
}

func TestDetectUnauthorizedNetworkMCPMessage(t *testing.T) {
	src := `@mcp.tool()
def fetch_data(query: str) -> str:
    """Fetch data."""
    return requests.get(query).text
`
	c, found := detectUnauthorizedNetwork(src)
	if !found {
		t.Fatal("expected detectUnauthorizedNetwork to fire")
	}
	if len(c.Evidence) == 0 {
		t.Fatal("expected evidence to be populated")
	}
	if got := c.Evidence[0].Detail; !strings.Contains(got, "MCP tool 'fetch_data'") {
		t.Errorf("expected MCP-aware detail message, got: %q", got)
	}
}

// TestNoDoubleCounting confirms the new agent-specific checks and the existing
// shell-injection check fire as distinct, non-overlapping findings (different
// Titles) rather than duplicating the same evidence under two names.
func TestNoDoubleCounting(t *testing.T) {
	src := `from agents import function_tool
import subprocess

@function_tool
def run(cmd: str) -> str:
    """Run a command."""
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
`
	titles := map[string]bool{}
	if c, ok := detectOverPrivilegedToolDefinition(src); ok {
		titles[c.Title] = true
	}
	if c, ok := detectShellInjection(src); ok {
		titles[c.Title] = true
	}
	if len(titles) != 2 {
		t.Errorf("expected 2 distinct findings (over-privileged tool + shell injection), got titles: %v", titles)
	}
}

// ── Go detector tests ─────────────────────────────────────────────────────────

func TestDetectGoHardcodedSecret(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "var with api_key literal fires",
			src:       `var apiKey = "sk-proj-abc123xyz789"`,
			wantFound: true,
		},
		{
			name:      "const password literal fires",
			src:       `const password = "supersecret99"`,
			wantFound: true,
		},
		{
			name:      "ghp_ prefix fires",
			src:       `token := "ghp_abcdefghijklmnop"`,
			wantFound: true,
		},
		{
			name:      "env var read does not fire",
			src:       `apiKey := os.Getenv("OPENAI_API_KEY")`,
			wantFound: false,
		},
		{
			name:      "placeholder value does not fire",
			src:       `const apiKey = "your-api-key-here"`,
			wantFound: false,
		},
		{
			name:      "comment line does not fire",
			src:       `// apiKey = "sk-real-secret-value"`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectGoHardcodedSecret(c.src)
			if found != c.wantFound {
				t.Errorf("detectGoHardcodedSecret(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

func TestDetectGoUnsafeExec(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "exec.Command fires",
			src:       `cmd := exec.Command("bash", userInput)`,
			wantFound: true,
		},
		{
			name:      "os.StartProcess fires",
			src:       `os.StartProcess("/bin/sh", args, nil)`,
			wantFound: true,
		},
		{
			name:      "no exec does not fire",
			src:       `fmt.Println("hello world")`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectGoUnsafeExec(c.src)
			if found != c.wantFound {
				t.Errorf("detectGoUnsafeExec(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

// ── JS/TS detector tests ──────────────────────────────────────────────────────

func TestDetectJSHardcodedSecret(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "const apiKey literal fires",
			src:       `const apiKey = "sk-abc123xyzlong"`,
			wantFound: true,
		},
		{
			name:      "ghp_ prefix fires",
			src:       `const token = "ghp_abcdefghijklmno"`,
			wantFound: true,
		},
		{
			name:      "process.env read does not fire",
			src:       `const apiKey = process.env.OPENAI_API_KEY`,
			wantFound: false,
		},
		{
			name:      "template literal does not fire",
			src:       `const key = "your-key-here"`,
			wantFound: false,
		},
		{
			name:      "comment line does not fire",
			src:       `// const apiKey = "sk-real-secret"`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectJSHardcodedSecret(c.src)
			if found != c.wantFound {
				t.Errorf("detectJSHardcodedSecret(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

func TestDetectJSUnauthorizedNetwork(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "fetch fires",
			src:       `const res = await fetch("https://api.example.com/data")`,
			wantFound: true,
		},
		{
			name:      "axios.get fires",
			src:       `const res = await axios.get("https://api.example.com/data")`,
			wantFound: true,
		},
		{
			name:      "declared outbound does not fire",
			src:       "// Outbound: api.example.com:443\nconst res = await fetch(\"https://api.example.com/data\")",
			wantFound: false,
		},
		{
			name:      "no network call does not fire",
			src:       `const x = 1 + 1`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectJSUnauthorizedNetwork(c.src)
			if found != c.wantFound {
				t.Errorf("detectJSUnauthorizedNetwork(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

func TestDetectJSMissingTimeout(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "fetch without signal fires",
			src:       `const res = await fetch("https://api.example.com")`,
			wantFound: true,
		},
		{
			name:      "fetch with AbortSignal does not fire",
			src:       `const res = await fetch("https://api.example.com", { signal: AbortSignal.timeout(5000) })`,
			wantFound: false,
		},
		{
			name:      "axios without timeout fires",
			src:       `const res = await axios.get("https://api.example.com")`,
			wantFound: true,
		},
		{
			name:      "axios with timeout does not fire",
			src:       "const res = await axios.get(url, { timeout: 5000 })",
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectJSMissingTimeout(c.src)
			if found != c.wantFound {
				t.Errorf("detectJSMissingTimeout(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

func TestDetectJSMissingErrorHandling(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "bare await fetch fires",
			src:       `const res = await fetch("https://api.example.com")`,
			wantFound: true,
		},
		{
			name:      "await fetch inside try does not fire",
			src:       "try {\n  const res = await fetch(\"https://api.example.com\")\n} catch(e) {}",
			wantFound: false,
		},
		{
			name:      "promise fetch with .catch does not fire",
			src:       `fetch("https://api.example.com").then(r => r.json()).catch(console.error)`,
			wantFound: false,
		},
		{
			name:      "no fetch does not fire",
			src:       `const x = 42`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectJSMissingErrorHandling(c.src)
			if found != c.wantFound {
				t.Errorf("detectJSMissingErrorHandling(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

// ── Ruby detector tests ───────────────────────────────────────────────────────

func TestDetectRubyHardcodedSecret(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "api_key literal fires",
			src:       `api_key = "sk-abc123xyzlong"`,
			wantFound: true,
		},
		{
			name:      "env var read does not fire",
			src:       `api_key = ENV['OPENAI_API_KEY']`,
			wantFound: false,
		},
		{
			name:      "interpolated string does not fire",
			src:       `token = "#{ENV['TOKEN']}"`,
			wantFound: false,
		},
		{
			name:      "comment does not fire",
			src:       `# api_key = "sk-real-secret"`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectRubyHardcodedSecret(c.src)
			if found != c.wantFound {
				t.Errorf("detectRubyHardcodedSecret(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

func TestDetectRubyUnauthorizedNetwork(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "Net::HTTP fires",
			src:       `response = Net::HTTP.get(URI("https://api.example.com"))`,
			wantFound: true,
		},
		{
			name:      "RestClient fires",
			src:       `response = RestClient.get("https://api.example.com")`,
			wantFound: true,
		},
		{
			name:      "declared outbound does not fire",
			src:       "# Outbound: api.example.com:443\nresponse = Net::HTTP.get(URI(url))",
			wantFound: false,
		},
		{
			name:      "no network call does not fire",
			src:       `puts "hello world"`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectRubyUnauthorizedNetwork(c.src)
			if found != c.wantFound {
				t.Errorf("detectRubyUnauthorizedNetwork(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

func TestDetectRubyMissingTimeout(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "Net::HTTP.new without timeout fires",
			src:       "http = Net::HTTP.new(\"api.example.com\", 443)\nhttp.use_ssl = true\nresponse = http.get(\"/v1/data\")",
			wantFound: true,
		},
		{
			name:      "Net::HTTP.new with open_timeout does not fire",
			src:       "http = Net::HTTP.new(\"api.example.com\", 443)\nhttp.open_timeout = 5\nhttp.read_timeout = 10\nresponse = http.get(\"/v1/data\")",
			wantFound: false,
		},
		{
			name:      "no Net::HTTP.new does not fire",
			src:       `response = Net::HTTP.get(URI("https://api.example.com"))`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectRubyMissingTimeout(c.src)
			if found != c.wantFound {
				t.Errorf("detectRubyMissingTimeout(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

// ── Shell detector tests ──────────────────────────────────────────────────────

func TestDetectShellHardcodedSecret(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "API_KEY with literal fires",
			src:       `API_KEY="sk-abc123xyzlong"`,
			wantFound: true,
		},
		{
			name:      "TOKEN with literal fires",
			src:       `TOKEN=ghp_abcdefghijklmno`,
			wantFound: true,
		},
		{
			name:      "env var reference does not fire",
			src:       `API_KEY=$OPENAI_API_KEY`,
			wantFound: false,
		},
		{
			name:      "command substitution does not fire",
			src:       `API_KEY=$(vault kv get -field=key secret/api)`,
			wantFound: false,
		},
		{
			name:      "comment does not fire",
			src:       `# API_KEY="sk-real-secret"`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectShellHardcodedSecret(c.src)
			if found != c.wantFound {
				t.Errorf("detectShellHardcodedSecret(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

func TestDetectShellUnsafeCurlWget(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "curl pipe to sh fires",
			src:       `curl https://install.example.com/script.sh | sh`,
			wantFound: true,
		},
		{
			name:      "curl pipe to bash fires",
			src:       `curl -s https://get.example.com | bash`,
			wantFound: true,
		},
		{
			name:      "curl without --fail fires",
			src:       `curl https://api.example.com/data -o output.json`,
			wantFound: true,
		},
		{
			name:      "curl with --fail does not fire",
			src:       `curl --fail https://api.example.com/data -o output.json`,
			wantFound: false,
		},
		{
			name:      "curl with -f does not fire",
			src:       `curl -f https://api.example.com/data -o output.json`,
			wantFound: false,
		},
		{
			name:      "no curl does not fire",
			src:       `echo "hello world"`,
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectShellUnsafeCurlWget(c.src)
			if found != c.wantFound {
				t.Errorf("detectShellUnsafeCurlWget(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}

func TestDetectShellMissingSetE(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantFound bool
	}{
		{
			name:      "script without set -e fires",
			src:       "#!/bin/bash\necho \"starting\"\ncurl https://api.example.com/data",
			wantFound: true,
		},
		{
			name:      "script with set -e does not fire",
			src:       "#!/bin/bash\nset -e\necho \"starting\"",
			wantFound: false,
		},
		{
			name:      "script with set -euo pipefail does not fire",
			src:       "#!/bin/bash\nset -euo pipefail\necho \"starting\"",
			wantFound: false,
		},
		{
			name:      "empty script does not fire",
			src:       "# just a comment\n",
			wantFound: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, found := detectShellMissingSetE(c.src)
			if found != c.wantFound {
				t.Errorf("detectShellMissingSetE(%q) found = %v, want %v", c.src, found, c.wantFound)
			}
		})
	}
}
