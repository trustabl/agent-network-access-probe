package fixer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/trustabl/probe/internal/llm"
	"github.com/trustabl/probe/internal/sandbox"
)

type Result struct {
	Candidate sandbox.Candidate `json:"candidate"`
	Original  string            `json:"original"`
	Fixed     string            `json:"fixed"`
	// FixedPath is set when the fix targets a different file than the source
	// (e.g. requirements.txt instead of the Python file being analysed).
	// Empty means write back to the source file path.
	FixedPath string `json:"fixed_path,omitempty"`
	// FilePath is the source file the candidate was found in, relative to
	// --source when possible. Populated only in JSON output mode so
	// programmatic consumers can attribute fixes to files.
	FilePath string `json:"file_path,omitempty"`
	Diff     string `json:"diff"`
	Summary  string `json:"summary"`
}

// Fix generates an AI-powered fix for a single candidate, reading the source from disk.
func Fix(sourcePath string, candidate sandbox.Candidate, client *llm.Client) (*Result, error) {
	src, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("could not read source file: %w", err)
	}
	return FixContent(sourcePath, string(src), candidate, client)
}

// FixContent is like Fix but uses the provided source instead of reading from disk.
// Use this when chaining fixes so each one builds on the previous output.
func FixContent(sourcePath, src string, candidate sandbox.Candidate, client *llm.Client) (*Result, error) {
	// Fully deterministic fixes — no LLM call needed.
	if r, ok := deterministicFix(sourcePath, src, candidate); ok {
		return r, nil
	}

	// Targeted per-function fix: avoids sending the full file and getting a partial response back.
	if strings.HasPrefix(candidate.Title, "Missing tool docstring") {
		return fixDocstrings(src, candidate, client)
	}

	system, user := buildPrompt(src, candidate)
	reply, err := client.Chat(system, user)
	if err != nil {
		return nil, fmt.Errorf("LLM error: %w", err)
	}

	fixed, summary, err := parseReply(reply)
	if err != nil {
		return nil, fmt.Errorf("LLM parse error: %w\nraw response:\n%s", err, reply)
	}

	// Sanity check: if the fixed code is less than 60% the length of the original,
	// the LLM likely deleted code instead of making a targeted fix. Reject it.
	if len(src) > 200 && len(fixed) < len(src)*6/10 {
		return nil, fmt.Errorf("LLM deleted too much code (original: %d chars, result: %d chars) — refusing to apply", len(src), len(fixed))
	}

	diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(src),
		B:        difflib.SplitLines(fixed),
		FromFile: "original",
		ToFile:   "fixed",
		Context:  3,
	})

	return &Result{
		Candidate: candidate,
		Original:  src,
		Fixed:     fixed,
		Diff:      diff,
		Summary:   summary,
	}, nil
}

func buildPrompt(src string, c sandbox.Candidate) (system, user string) {
	system = `You are an expert software engineer specializing in securing and hardening AI agent tools.
Your job is to apply minimal, targeted fixes to source code — only change what is necessary to resolve the reported issue.
Do not refactor, rename, reformat, or touch unrelated code.
Preserve all existing comments, structure, and logic outside the affected area.`

	var eb strings.Builder
	for _, e := range c.Evidence {
		fmt.Fprintf(&eb, "  - %s: %s\n", e.Label, e.Detail)
	}

	hint := ""
	if c.FixHint != "" {
		hint = "\nFIX GUIDANCE\n" + c.FixHint + "\n"
	}

	user = fmt.Sprintf(`ISSUE
Title:       %s
Severity:    %s
Description: %s
Evidence:
%s%s
SOURCE CODE
%s

Return your response in EXACTLY this format (no markdown, no extra text outside the tags):

<fixed_code>
[complete fixed source code with only the necessary change applied]
</fixed_code>
<summary>[one sentence: what you changed and why]</summary>`,
		c.Title, c.Severity, c.Description, eb.String(), hint, src)
	return system, user
}

func parseReply(reply string) (code, summary string, err error) {
	// Preferred format: <fixed_code>...</fixed_code>
	if code, err = extractTag(reply, "fixed_code"); err == nil && strings.TrimSpace(code) != "" {
		summary, _ = extractTag(reply, "summary")
		return code, summary, nil
	}

	// Fallback: markdown code fence ```[lang]\n...\n```
	if code = extractFence(reply); strings.TrimSpace(code) != "" {
		summary, _ = extractTag(reply, "summary")
		return code, summary, nil
	}

	return "", "", fmt.Errorf("could not extract code from LLM response (tried <fixed_code> tags and markdown fences)\nraw response:\n%s", reply)
}

func extractTag(s, tag string) (string, error) {
	_, after, ok := strings.Cut(s, "<"+tag+">")
	if !ok {
		return "", fmt.Errorf("tag <%s> not found", tag)
	}
	content, _, ok := strings.Cut(after, "</"+tag+">")
	if !ok {
		return "", fmt.Errorf("tag </%s> not found", tag)
	}
	return strings.TrimSpace(content), nil
}

func extractFence(s string) string {
	_, rest, ok := strings.Cut(s, "```")
	if !ok {
		return ""
	}
	// skip the opening fence line (```python, ```py, ``` etc.)
	if _, body, ok := strings.Cut(rest, "\n"); ok {
		rest = body
	}
	if code, _, ok := strings.Cut(rest, "```"); ok {
		return strings.TrimSpace(code)
	}
	return ""
}

// deterministicFix generates a fix without calling the LLM when the change is
// mechanical and fully determined by the evidence. Returns (nil, false) to fall
// through to the LLM path when no deterministic fix is available.
func deterministicFix(sourcePath, src string, c sandbox.Candidate) (*Result, bool) {
	switch c.Title {
	case "Missing dependency declarations":
		return fixMissingDeps(sourcePath, src, c)
	}
	return nil, false
}

// fixMissingDeps is the deterministic fix for "Missing dependency declarations".
//
// Strategy:
//   - If a requirements.txt (or .in) already exists in the source directory or
//     any ancestor, append the missing packages there.
//   - Otherwise, prepend an inline # requirements: comment block to the source file.
func fixMissingDeps(sourcePath, src string, c sandbox.Candidate) (*Result, bool) {
	var pkgs []string
	seen := map[string]bool{}
	for _, e := range c.Evidence {
		if pkg := extractPipName(e.Detail); pkg != "" && !seen[pkg] {
			seen[pkg] = true
			pkgs = append(pkgs, pkg)
		}
	}
	if len(pkgs) == 0 {
		return nil, false
	}

	// Drop packages that are local .py files or packages — they are not pip-installable.
	dir := filepath.Dir(sourcePath)
	filtered := pkgs[:0]
	for _, pkg := range pkgs {
		if !isLocalPyModule(dir, pkg) {
			filtered = append(filtered, pkg)
		}
	}
	pkgs = filtered
	if len(pkgs) == 0 {
		return nil, false
	}

	// Prefer appending to an existing requirements file over inline comment.
	if reqPath := findRequirementsFile(dir); reqPath != "" {
		return appendToRequirementsFile(reqPath, pkgs, c)
	}

	// No requirements file found — prepend inline # requirements: block.
	var block strings.Builder
	block.WriteString("# requirements:\n")
	for _, p := range pkgs {
		fmt.Fprintf(&block, "#   %s\n", p)
	}
	block.WriteString("\n")
	fixed := block.String() + src
	diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(src), B: difflib.SplitLines(fixed),
		FromFile: "original", ToFile: "fixed", Context: 3,
	})
	return &Result{
		Candidate: c, Original: src, Fixed: fixed, Diff: diff,
		Summary: "Added # requirements: block declaring " + strings.Join(pkgs, ", "),
	}, true
}

// isLocalPyModule returns true if name is a local Python file or package in dir
// (name.py or name/__init__.py). Used to avoid adding local imports to requirements.
func isLocalPyModule(dir, name string) bool {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if _, err := os.Stat(filepath.Join(dir, name+".py")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, name, "__init__.py")); err == nil {
		return true
	}
	return false
}

// findRequirementsFile walks up from dir looking for requirements.txt or
// requirements.in. Returns the first path found, or "" if none exists.
func findRequirementsFile(dir string) string {
	// Resolve to absolute so filepath.Dir can walk all the way to the root.
	// Without this, a relative dir like "." makes filepath.Dir return "."
	// forever and the loop terminates immediately.
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	names := []string{"requirements.txt", "requirements.in"}
	cur := dir
	for {
		for _, name := range names {
			p := filepath.Join(cur, name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}

// appendToRequirementsFile adds any missing packages to an existing requirements
// file. The Result targets reqPath (via FixedPath) rather than the source file.
func appendToRequirementsFile(reqPath string, pkgs []string, c sandbox.Candidate) (*Result, bool) {
	existing, _ := os.ReadFile(reqPath)
	existingStr := string(existing)

	var toAdd []string
	for _, pkg := range pkgs {
		if !strings.Contains(existingStr, pkg) {
			toAdd = append(toAdd, pkg)
		}
	}
	if len(toAdd) == 0 {
		return nil, false
	}

	fixed := strings.TrimRight(existingStr, "\n") + "\n" + strings.Join(toAdd, "\n") + "\n"
	diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(existingStr), B: difflib.SplitLines(fixed),
		FromFile: reqPath, ToFile: reqPath, Context: 3,
	})
	return &Result{
		Candidate: c,
		Original:  existingStr,
		Fixed:     fixed,
		FixedPath: reqPath,
		Diff:      diff,
		Summary:   "Added " + strings.Join(toAdd, ", ") + " to " + filepath.Base(reqPath),
	}, true
}

// extractPipName pulls the pip package name from an evidence detail string.
// Handles two formats:
//
//	Static analysis: "import 'X' (pip: Y) is not declared..."  → Y
//	Sandbox output:  "ModuleNotFoundError: No module named 'X'" → X
func extractPipName(detail string) string {
	if _, after, ok := strings.Cut(detail, "(pip: "); ok {
		if pkg, _, ok := strings.Cut(after, ")"); ok {
			return strings.TrimSpace(pkg)
		}
	}
	if _, after, ok := strings.Cut(detail, "No module named '"); ok {
		if name, _, ok := strings.Cut(after, "'"); ok {
			return strings.TrimSpace(name)
		}
	}
	return ""
}

var reDocEvidence = regexp.MustCompile(`'([^']+)'\s+on\s+line\s+(\d+)`)

// cleanDocstringText strips markdown code fences, triple quotes, and extra
// whitespace from an LLM-generated docstring, then collapses to a single line.
func cleanDocstringText(s string) string {
	s = strings.TrimSpace(s)
	// Strip markdown code fence wrapper (```python\n...\n``` or ```\n...\n```)
	if _, after, ok := strings.Cut(s, "```"); ok {
		// skip the optional language tag on the first line
		if _, body, ok := strings.Cut(after, "\n"); ok {
			after = body
		}
		// strip closing fence
		if before, _, ok := strings.Cut(after, "```"); ok {
			s = strings.TrimSpace(before)
		}
	}
	// Strip surrounding triple or single quotes the model may have added
	s = strings.TrimPrefix(s, `"""`)
	s = strings.TrimSuffix(s, `"""`)
	s = strings.Trim(s, `"'`)
	// Collapse to first non-empty line — docstrings must be single-line here
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return strings.TrimSpace(s)
}

// parseDocstringEvidence extracts the function name and 1-based line number from
// an evidence detail: "'funcName' on line N has no docstring — ..."
func parseDocstringEvidence(detail string) (funcName string, lineNum int) {
	m := reDocEvidence.FindStringSubmatch(detail)
	if m == nil {
		return "", 0
	}
	n, _ := strconv.Atoi(m[2])
	return m[1], n
}

// fixDocstrings inserts docstrings into each flagged function via small focused LLM
// calls (one per function), then splices them into the source. This avoids the
// "return the full 10k-char file" problem that causes local models to truncate.
func fixDocstrings(src string, c sandbox.Candidate, client *llm.Client) (*Result, error) {
	lines := strings.Split(src, "\n")

	type insertion struct {
		afterIdx  int    // 0-based index of the def line; docstring goes at afterIdx+1
		docstring string // content only, no triple quotes
		indent    string
	}
	var insertions []insertion

	for _, e := range c.Evidence {
		_, lineNum := parseDocstringEvidence(e.Detail)
		if lineNum <= 0 || lineNum > len(lines) {
			continue
		}
		defIdx := lineNum - 1
		defLine := lines[defIdx]

		// Derive body indent: def indent + 4 spaces.
		defIndent := defLine[:len(defLine)-len(strings.TrimLeft(defLine, " \t"))]
		bodyIndent := defIndent + "    "

		// Send just the function context (def line + up to 8 body lines) to the LLM.
		end := min(defIdx+9, len(lines))
		snippet := strings.Join(lines[defIdx:end], "\n")

		docText, err := client.Chat(
			"You are a Python documentation expert. Write concise, accurate docstrings.",
			"Write a one-line docstring for this Python function.\n"+
				"Return ONLY the docstring content — no triple quotes, no code fences, no def line, just the plain sentence.\n\n"+snippet,
		)
		if err != nil {
			continue
		}
		docText = cleanDocstringText(docText)

		insertions = append(insertions, insertion{afterIdx: defIdx, docstring: docText, indent: bodyIndent})
	}

	if len(insertions) == 0 {
		return &Result{Candidate: c, Original: src, Fixed: src, Diff: "", Summary: "no docstrings generated"}, nil
	}

	// Insert from highest line to lowest so earlier indices stay valid.
	sort.Slice(insertions, func(i, j int) bool { return insertions[i].afterIdx > insertions[j].afterIdx })

	result := make([]string, len(lines))
	copy(result, lines)
	for _, ins := range insertions {
		docLine := ins.indent + `"""` + ins.docstring + `"""`
		pos := ins.afterIdx + 1
		result = append(result[:pos:pos], append([]string{docLine}, result[pos:]...)...)
	}

	fixed := strings.Join(result, "\n")
	diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(src), B: difflib.SplitLines(fixed),
		FromFile: "original", ToFile: "fixed", Context: 3,
	})
	return &Result{
		Candidate: c, Original: src, Fixed: fixed, Diff: diff,
		Summary: fmt.Sprintf("Added docstrings to %d function(s)", len(insertions)),
	}, nil
}
