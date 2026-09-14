package sandbox

import (
	"regexp"
	"strings"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Evidence is a single runtime event that backs a fix candidate.
type Evidence struct {
	Label   string `json:"label"`
	Detail  string `json:"detail"`
	RawLine string `json:"raw_line"`
	Source  string `json:"source"` // "openshell_policy" | "tool_output"
}

// Candidate is a grouped finding surfaced from runtime evidence.
type Candidate struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`    // "critical", "warning", "info"
	ScoreImpact int        `json:"score_impact"` // negative
	Evidence    []Evidence `json:"evidence"`
	FixHint     string     `json:"fix_hint,omitempty"` // concrete fix guidance passed to the LLM
}

type rule struct {
	contains    string
	candidateID string
	label       string
	source      string
	detail      func(line string) string
}

func extractNetworkDest(line string) string {
	if idx := strings.Index(line, "-> "); idx != -1 {
		rest := strings.Fields(line[idx+3:])
		if len(rest) > 0 {
			host := strings.TrimRight(rest[0], " ")
			return "Outbound connection to " + host + " was blocked by sandbox policy."
		}
	}
	return "Tool attempted an outbound network call that was blocked by the sandbox policy."
}

var rules = []rule{
	{
		contains:    "DENIED",
		candidateID: "unauthorized_network",
		label:       "Policy denied",
		source:      "openshell_policy",
		detail:      extractNetworkDest,
	},
	{
		contains:    "Traceback",
		candidateID: "unhandled_exception",
		label:       "Agent crash",
		source:      "tool_output",
		detail: func(line string) string {
			return "Tool raised an unhandled exception that would crash the agent run."
		},
	},
	{
		contains:    "ModuleNotFoundError",
		candidateID: "missing_dependency",
		label:       "Missing dependency",
		source:      "tool_output",
		detail: func(line string) string {
			return strings.TrimSpace(line)
		},
	},
	// Docker network isolation errors — must appear before the generic "Error" rule.
	{
		contains:    "dial tcp",
		candidateID: "unauthorized_network",
		label:       "Network blocked",
		source:      "docker_network",
		detail: func(line string) string {
			return "Docker network isolation blocked an outbound TCP connection: " + strings.TrimSpace(line)
		},
	},
	{
		contains:    "network unreachable",
		candidateID: "unauthorized_network",
		label:       "Network blocked",
		source:      "docker_network",
		detail: func(line string) string {
			return "Docker network isolation blocked an outbound connection attempt."
		},
	},
	{
		contains:    "urlopen error",
		candidateID: "unauthorized_network",
		label:       "Network blocked",
		source:      "docker_network",
		detail: func(line string) string {
			return "Docker network isolation blocked an outbound HTTP connection: " + strings.TrimSpace(line)
		},
	},
	{
		contains:    "ConnectionError",
		candidateID: "unauthorized_network",
		label:       "Network blocked",
		source:      "docker_network",
		detail: func(line string) string {
			return "Docker network isolation blocked an outbound connection: " + strings.TrimSpace(line)
		},
	},
	{
		contains:    "gaierror",
		candidateID: "unauthorized_network",
		label:       "Network blocked",
		source:      "docker_network",
		detail: func(line string) string {
			return "Docker network isolation blocked DNS resolution for an outbound connection."
		},
	},
	{
		contains:    "Error",
		candidateID: "unhandled_exception",
		label:       "Agent crash",
		source:      "tool_output",
		detail: func(line string) string {
			if idx := strings.Index(line, "Error"); idx != -1 {
				return strings.TrimSpace(line[idx:])
			}
			return line
		},
	},
	{
		contains:    "file access",
		candidateID: "unsafe_file_access",
		label:       "Unsafe file access",
		source:      "openshell_policy",
		detail: func(line string) string {
			return "Tool accessed filesystem paths outside the expected sandbox boundary."
		},
	},
	{
		contains:    "timeout",
		candidateID: "missing_timeout",
		label:       "Timeout",
		source:      "openshell_policy",
		detail: func(line string) string {
			return "Tool timed out with no retry attempted and no fallback returned."
		},
	},
	{
		contains:    "DeprecationWarning",
		candidateID: "deprecated_usage",
		label:       "Deprecated API usage",
		source:      "tool_output",
		detail: func(line string) string {
			if idx := strings.Index(line, "DeprecationWarning:"); idx != -1 {
				return strings.TrimSpace(line[idx+len("DeprecationWarning:"):])
			}
			return line
		},
	},
	{
		contains:    "ResourceWarning",
		candidateID: "resource_warning",
		label:       "Resource warning",
		source:      "tool_output",
		detail: func(line string) string {
			if idx := strings.Index(line, "ResourceWarning:"); idx != -1 {
				return strings.TrimSpace(line[idx+len("ResourceWarning:"):])
			}
			return line
		},
	},
	{
		contains:    "UserWarning",
		candidateID: "silent_fallback",
		label:       "Silent fallback detected",
		source:      "tool_output",
		detail: func(line string) string {
			if idx := strings.Index(line, "UserWarning:"); idx != -1 {
				return strings.TrimSpace(line[idx+len("UserWarning:"):])
			}
			return line
		},
	},
}

var candidateTemplates = map[string]Candidate{
	"unauthorized_network": {
		Title:       "Unauthorized network calls — tool may exfiltrate data",
		Description: "The tool makes outbound network connections that are not declared in its metadata. The network call is intentional and must remain — it just needs to be documented so the agent runtime can enforce least-privilege policy.",
		Severity:    "critical",
		ScoreImpact: -25,
		FixHint:     "Add a comment directly above the function signature that declares the outbound endpoint using this exact format: '# Outbound: api.example.com:443 — fetches alert data'. Use '#' for Python, '//' for Go/JS/TS. The network call itself MUST remain completely unchanged. Do not remove, stub, disable, or comment out any network code.",
	},
	"unhandled_exception": {
		Title:       "No error handling — tool crashes agent",
		Description: "The tool raises unhandled exceptions that would terminate the entire agent run without recovery.",
		Severity:    "critical",
		ScoreImpact: -25,
		FixHint:     "Wrap the body of the function that makes external calls in a try/except block. Catch Exception as e and return a safe error string instead of raising. Example: def my_tool(arg):\n    try:\n        # existing body here\n        return result\n    except Exception as e:\n        return f'Tool error: {e}'\nDo NOT change the function signature, imports, or any other part of the file.",
	},
	"missing_dependency": {
		Title:       "Missing dependency declarations",
		Description: "The tool imports packages that are not declared in any requirements file, making deployment unpredictable.",
		Severity:    "warning",
		ScoreImpact: -10,
		FixHint:     "Add a requirements comment block at the very top of the file (before any imports) listing each third-party package on its own line. Use exactly this format:\n# requirements:\n#   package-name-1\n#   package-name-2\nOnly list packages that are actually imported and are not Python standard library modules.",
	},
	"unsafe_file_access": {
		Title:       "Unsafe filesystem access",
		Description: "The tool accesses filesystem paths outside the expected sandbox boundary, risking data leakage or corruption.",
		Severity:    "warning",
		ScoreImpact: -15,
	},
	"missing_timeout": {
		Title:       "No timeout handling — tool can hang agent indefinitely",
		Description: "The tool has no timeout on network or IO operations. A slow or degraded dependency will stall the agent with no retry or fallback.",
		Severity:    "critical",
		ScoreImpact: -20,
		FixHint:     "Add a timeout to the network/IO call. Python urlopen: add timeout=10. Python requests: add timeout=(3, 10). Go http.Client: set Timeout: 10 * time.Second on the client struct.",
	},
	"deprecated_usage": {
		Title:       "Deprecated API usage",
		Description: "The tool uses deprecated APIs that may be removed in future runtime versions, causing silent breakage.",
		Severity:    "warning",
		ScoreImpact: -10,
	},
	"resource_warning": {
		Title:       "Unbounded resource usage",
		Description: "The tool may consume excessive memory or file handles without limits, risking agent runtime instability.",
		Severity:    "warning",
		ScoreImpact: -10,
	},
	"silent_fallback": {
		Title:       "Silent fallback — unexpected data routing",
		Description: "The tool falls back to hardcoded values on invalid input without surfacing an error, potentially routing data to unintended destinations.",
		Severity:    "warning",
		ScoreImpact: -15,
	},
}

// ParseLogs turns raw OpenShell log output into grouped fix candidates.
func ParseLogs(logs string) []Candidate {
	groups := map[string][]Evidence{}

	pypiHosts := []string{"pypi.org", "files.pythonhosted.org"}

	for _, line := range strings.Split(logs, "\n") {
		line = ansi.ReplaceAllString(strings.TrimSpace(line), "")
		if line == "" {
			continue
		}
		isPypi := false
		for _, h := range pypiHosts {
			if strings.Contains(line, h) {
				isPypi = true
				break
			}
		}
		if isPypi {
			continue
		}
		for _, r := range rules {
			if strings.Contains(line, r.contains) {
				groups[r.candidateID] = append(groups[r.candidateID], Evidence{
					Label:   r.label,
					Detail:  r.detail(line),
					RawLine: line,
					Source:  r.source,
				})
				break
			}
		}
	}

	var candidates []Candidate
	for id, evidence := range groups {
		tmpl, ok := candidateTemplates[id]
		if !ok {
			continue
		}
		tmpl.Evidence = evidence
		candidates = append(candidates, tmpl)
	}
	return candidates
}
