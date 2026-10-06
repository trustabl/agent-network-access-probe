package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/trustabl/agent-network-access-probe/internal/sandbox"
)

// stdlibModules is a curated set of Python 3 standard-library top-level names.
var stdlibModules = map[string]bool{
	"__future__": true, "_thread": true, "abc": true, "aifc": true,
	"argparse": true, "array": true, "ast": true, "asynchat": true,
	"asyncio": true, "asyncore": true, "atexit": true, "audioop": true,
	"base64": true, "bdb": true, "binascii": true, "bisect": true,
	"builtins": true, "bz2": true, "calendar": true, "cgi": true,
	"cgitb": true, "chunk": true, "cmath": true, "cmd": true,
	"code": true, "codecs": true, "codeop": true, "collections": true,
	"colorsys": true, "compileall": true, "concurrent": true,
	"configparser": true, "contextlib": true, "contextvars": true,
	"copy": true, "copyreg": true, "cProfile": true, "csv": true,
	"ctypes": true, "curses": true, "dataclasses": true, "datetime": true,
	"dbm": true, "decimal": true, "difflib": true, "dis": true,
	"doctest": true, "email": true, "encodings": true, "enum": true,
	"errno": true, "faulthandler": true, "filecmp": true, "fileinput": true,
	"fnmatch": true, "fractions": true, "ftplib": true, "functools": true,
	"gc": true, "getopt": true, "getpass": true, "gettext": true,
	"glob": true, "grp": true, "gzip": true, "hashlib": true,
	"heapq": true, "hmac": true, "html": true, "http": true,
	"imaplib": true, "importlib": true, "inspect": true, "io": true,
	"ipaddress": true, "itertools": true, "json": true, "keyword": true,
	"linecache": true, "locale": true, "logging": true, "lzma": true,
	"mailbox": true, "marshal": true, "math": true, "mimetypes": true,
	"mmap": true, "modulefinder": true, "multiprocessing": true,
	"netrc": true, "numbers": true, "operator": true, "optparse": true,
	"os": true, "pathlib": true, "pdb": true, "pickle": true,
	"pickletools": true, "pkgutil": true, "platform": true, "plistlib": true,
	"poplib": true, "posix": true, "posixpath": true, "pprint": true,
	"profile": true, "pstats": true, "pty": true, "pwd": true,
	"py_compile": true, "pyclbr": true, "pydoc": true, "queue": true,
	"quopri": true, "random": true, "re": true, "readline": true,
	"reprlib": true, "resource": true, "rlcompleter": true, "runpy": true,
	"sched": true, "secrets": true, "select": true, "selectors": true,
	"shelve": true, "shlex": true, "shutil": true, "signal": true,
	"site": true, "smtpd": true, "smtplib": true, "socket": true,
	"socketserver": true, "sqlite3": true, "ssl": true, "stat": true,
	"statistics": true, "string": true, "stringprep": true, "struct": true,
	"subprocess": true, "sys": true, "sysconfig": true, "syslog": true,
	"tabnanny": true, "tarfile": true, "tempfile": true, "termios": true,
	"textwrap": true, "threading": true, "time": true, "timeit": true,
	"tkinter": true, "token": true, "tokenize": true, "tomllib": true,
	"trace": true, "traceback": true, "tracemalloc": true, "tty": true,
	"types": true, "typing": true, "unicodedata": true, "unittest": true,
	"urllib": true, "uuid": true, "venv": true, "warnings": true,
	"wave": true, "weakref": true, "webbrowser": true, "wsgiref": true,
	"xml": true, "xmlrpc": true, "zipapp": true, "zipfile": true,
	"zipimport": true, "zlib": true, "zoneinfo": true,
}

// IsLocalModule returns true if name resolves to a local Python file or package
// reachable from dir. Walks up to 10 levels so packages at the repo root are
// found even when the tool lives in a subdirectory.
func IsLocalModule(dir, name string) bool {
	return findLocalPackagePath(dir, name) != ""
}

// findLocalPackagePath walks up from dir (up to 10 levels) looking for a Python
// package or module named name. Returns the absolute path on success, "" if not found.
// Handles both regular packages (with __init__.py) and namespace packages (without).
func findLocalPackagePath(dir, name string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	cur := dir
	for range 10 {
		pkgDir := filepath.Join(cur, name)
		// Regular package: has __init__.py
		if _, err := os.Stat(filepath.Join(pkgDir, "__init__.py")); err == nil {
			return pkgDir
		}
		// Single-file module
		if _, err := os.Stat(filepath.Join(cur, name+".py")); err == nil {
			return filepath.Join(cur, name+".py")
		}
		// Namespace package: directory exists and has Python content (no __init__.py)
		if info, err := os.Stat(pkgDir); err == nil && info.IsDir() && hasPythonContent(pkgDir) {
			return pkgDir
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
	return ""
}

// hasPythonContent returns true if dir contains at least one .py file or a
// subdirectory that itself contains .py files (one level deep is enough to
// identify a namespace package like examples/tools/shell.py).
func hasPythonContent(dir string) bool {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			if strings.HasSuffix(e.Name(), ".py") {
				return true
			}
			if e.IsDir() {
				inner, _ := os.ReadDir(filepath.Join(dir, e.Name()))
				for _, ie := range inner {
					if strings.HasSuffix(ie.Name(), ".py") {
						return true
					}
				}
			}
		}
	}
	return false
}

// FindLocalPackages returns absolute paths to local Python packages/modules that
// are imported by the tool at filePath but are not pip-installable. These must be
// uploaded to the sandbox so the tool can import them at runtime.
func FindLocalPackages(filePath, src string) []string {
	if filepath.Ext(filePath) != ".py" {
		return nil
	}
	absFile, _ := filepath.Abs(filePath)
	dir := filepath.Dir(absFile)

	var paths []string
	seenName := map[string]bool{}
	seenPath := map[string]bool{}
	for _, m := range reImport.FindAllStringSubmatch(src, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if dot := strings.Index(name, "."); dot != -1 {
			name = name[:dot]
		}
		if name == "" || stdlibModules[name] || seenName[name] {
			continue
		}
		if _, ok := knownThirdParty[name]; ok {
			continue
		}
		seenName[name] = true
		if p := findLocalPackagePath(dir, name); p != "" && !seenPath[p] {
			seenPath[p] = true
			paths = append(paths, p)
		}
	}
	return paths
}

// isDeclaredInRequirements returns true if pkgName is listed in a requirements
// file found anywhere up the directory tree. It reads requirements.txt /
// requirements.in line by line (stripping version specifiers), and does a
// simple substring search for pyproject.toml / setup.py / setup.cfg.
func isDeclaredInRequirements(dir, pkgName string) bool {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	lower := strings.ToLower(pkgName)
	cur := dir
	for {
		for _, fname := range []string{"requirements.txt", "requirements.in"} {
			data, err := os.ReadFile(filepath.Join(cur, fname))
			if err != nil {
				continue
			}
			if packageInReqsTxt(string(data), lower) {
				return true
			}
		}
		for _, fname := range []string{"pyproject.toml", "setup.py", "setup.cfg"} {
			data, err := os.ReadFile(filepath.Join(cur, fname))
			if err != nil {
				continue
			}
			if strings.Contains(strings.ToLower(string(data)), lower) {
				return true
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false
		}
		cur = parent
	}
}

// packageInReqsTxt checks whether pkgLower (already lowercased) appears as a
// declared package in requirements.txt content. Strips version specifiers,
// extras, and environment markers before comparing.
func packageInReqsTxt(content, pkgLower string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Package name ends at the first version specifier, extra, or marker.
		end := strings.IndexAny(line, "><=![ ;")
		if end == -1 {
			end = len(line)
		}
		if strings.ToLower(strings.TrimSpace(line[:end])) == pkgLower {
			return true
		}
	}
	return false
}

// HasRequirementsFile returns true if dir or any ancestor directory contains a
// Python dependency manifest. Walks up the tree so a pyproject.toml at the
// repo root is found even when the entrypoint is several levels deep.
func HasRequirementsFile(dir string) bool {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	manifests := []string{"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg"}
	cur := dir
	for {
		for _, name := range manifests {
			if _, err := os.Stat(filepath.Join(cur, name)); err == nil {
				return true
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break // reached filesystem root
		}
		cur = parent
	}
	return false
}

// knownThirdParty maps Python import names to their pip package names.
// Only imports in this map are pre-installed, preventing attempts to pip-install
// local modules or ambiguous single-word names.
var knownThirdParty = map[string]string{
	"requests":        "requests",
	"httpx":           "httpx",
	"aiohttp":         "aiohttp",
	"anthropic":       "anthropic",
	"openai":          "openai",
	"agents":          "openai-agents",
	"langchain":       "langchain",
	"mcp":             "mcp",
	"pydantic":        "pydantic",
	"fastapi":         "fastapi",
	"structlog":       "structlog",
	"dotenv":          "python-dotenv",
	"boto3":           "boto3",
	"botocore":        "botocore",
	"google":          "google-generativeai",
	"crewai":          "crewai",
	"autogen":         "pyautogen",
	"semantic_kernel": "semantic-kernel",
	"llama_index":     "llama-index",
	"haystack":        "farm-haystack",
}

// ExtractImports returns the pip package names for known third-party imports in
// a Python file. Import-to-pip name mapping is handled automatically (e.g.
// "agents" → "openai-agents").
func ExtractImports(filePath, src string) []string {
	if filepath.Ext(filePath) != ".py" {
		return nil
	}
	seen := map[string]bool{}
	var pkgs []string
	for _, m := range reImport.FindAllStringSubmatch(src, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if dot := strings.Index(name, "."); dot != -1 {
			name = name[:dot]
		}
		pipName, ok := knownThirdParty[name]
		if !ok || seen[pipName] {
			continue
		}
		seen[pipName] = true
		pkgs = append(pkgs, pipName)
	}
	return pkgs
}

// DetectsMutatingOperation reports whether src contains a call shape that
// performs a real-world side effect — a network write, a subprocess call, a
// filesystem delete, or destructive SQL — independent of what any docstring
// claims and regardless of language. Used to gate sandbox execution of a
// tool by default (see harness safety rules / Slice 5), not just to flag a
// description mismatch the way detectToolDescriptionMismatch does. Returns
// one Evidence entry per matching line, or nil if nothing matched.
func DetectsMutatingOperation(src string) []sandbox.Evidence {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if reMutatingOperation.MatchString(line) {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Mutating operation",
				Detail:  fmt.Sprintf("Line %d performs an operation with a real-world side effect", i+1),
				RawLine: trimmed,
				Source:  "static_analysis",
			})
		}
	}
	return evidence
}

// Analyze runs lightweight static analysis on source code and returns findings.
// filePath is the full path to the file and is used for language detection and
// locating dependency manifests. Results are tagged with Source "static_analysis".
func Analyze(filePath, src string) []sandbox.Candidate {
	switch filepath.Ext(filePath) {
	case ".py":
		return analyzePython(filePath, src)
	case ".go":
		return analyzeGo(src)
	case ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs":
		return analyzeJS(src)
	case ".rb":
		return analyzeRuby(src)
	case ".sh", ".bash":
		return analyzeShell(src)
	default:
		return nil
	}
}

func analyzePython(filePath, src string) []sandbox.Candidate {
	dir := filepath.Dir(filePath)
	var candidates []sandbox.Candidate
	for _, fn := range []func(string) (sandbox.Candidate, bool){
		// Agent-specific rules first — these are the differentiators
		detectMissingDocstring,
		detectUnboundedResponse,
		detectPromptInjectionRisk,
		detectOverPrivilegedToolDefinition,
		detectToolDescriptionMismatch,
		detectUnrestrictedOpenAIToolSchema,
		// Security rules
		detectHardcodedSecret,
		detectShellInjection,
		detectInsecureDeserialization,
		detectMissingEnvCheck,
		detectMaliciousPackages,
		// Reliability rules
		detectMissingTimeout,
		detectUnauthorizedNetwork,
	} {
		if c, ok := fn(src); ok {
			candidates = append(candidates, c)
		}
	}
	if c, ok := detectMissingDependency(src, dir); ok {
		candidates = append(candidates, c)
	}
	return candidates
}

// toolFunctionSpan describes the line range of an agent-tool-decorated function.
type toolFunctionSpan struct {
	name      string
	defLine   int // index of the "def" line
	bodyStart int // first line index of the body
	bodyEnd   int // line index AFTER the last body line (exclusive)
}

// findToolFunctionSpans locates functions decorated with @function_tool,
// @mcp.tool(...), or @tool(...) — the common agent-framework tool-definition
// decorators — and returns each one's name and body line range. The body
// range is indentation-based: it ends at the first subsequent line whose
// indentation is not deeper than the def line's.
func findToolFunctionSpans(lines []string) []toolFunctionSpan {
	var spans []toolFunctionSpan
	pendingDecorator := false
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if reAgentToolDecorator.MatchString(trimmed) {
			pendingDecorator = true
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "@") {
			continue // blank line or another stacked decorator — keep waiting
		}
		m := reFuncDef.FindStringSubmatch(trimmed)
		if m == nil {
			pendingDecorator = false
			continue
		}
		if !pendingDecorator {
			continue
		}
		pendingDecorator = false
		baseIndent := len(lines[i]) - len(strings.TrimLeft(lines[i], " \t"))
		bodyEnd := len(lines)
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			indent := len(lines[j]) - len(strings.TrimLeft(lines[j], " \t"))
			if indent <= baseIndent {
				bodyEnd = j
				break
			}
		}
		spans = append(spans, toolFunctionSpan{name: m[1], defLine: i, bodyStart: i + 1, bodyEnd: bodyEnd})
	}
	return spans
}

// extractDocstring returns the text of the triple-quoted docstring that
// immediately follows defLineIdx (within a short lookahead window), or ""
// if none is found. Quote markers are left in place since callers only need
// substring/regex matching, not a clean string.
func extractDocstring(lines []string, defLineIdx int) string {
	for j := defLineIdx + 1; j < len(lines) && j <= defLineIdx+3; j++ {
		next := strings.TrimSpace(lines[j])
		if next == "" {
			continue
		}
		if !strings.HasPrefix(next, `"""`) && !strings.HasPrefix(next, `'''`) {
			return ""
		}
		quote := next[:3]
		if strings.Count(next, quote) >= 2 {
			return next // single-line docstring
		}
		var b strings.Builder
		b.WriteString(next)
		for k := j + 1; k < len(lines) && k <= j+15; k++ {
			b.WriteString(" ")
			b.WriteString(strings.TrimSpace(lines[k]))
			if strings.Contains(lines[k], quote) {
				break
			}
		}
		return b.String()
	}
	return ""
}

func detectOverPrivilegedToolDefinition(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for _, span := range findToolFunctionSpans(lines) {
		for j := span.bodyStart; j < span.bodyEnd; j++ {
			bodyTrimmed := strings.TrimSpace(lines[j])
			if bodyTrimmed == "" || strings.HasPrefix(bodyTrimmed, "#") {
				continue
			}
			switch {
			case reOsSystem.MatchString(lines[j]):
				evidence = append(evidence, sandbox.Evidence{
					Label:   "Unscoped shell execution in tool",
					Detail:  fmt.Sprintf("Agent tool '%s' calls os.system()/os.popen() on line %d — the LLM can run arbitrary shell commands through this tool", span.name, j+1),
					RawLine: bodyTrimmed,
					Source:  "static_analysis",
				})
			case reSubprocess.MatchString(lines[j]):
				evidence = append(evidence, sandbox.Evidence{
					Label:   "Unscoped subprocess execution in tool",
					Detail:  fmt.Sprintf("Agent tool '%s' calls subprocess.* on line %d with no allow-list — the LLM can run arbitrary commands through this tool", span.name, j+1),
					RawLine: bodyTrimmed,
					Source:  "static_analysis",
				})
			case reEvalExecCompile.MatchString(lines[j]):
				evidence = append(evidence, sandbox.Evidence{
					Label:   "Dynamic code execution in tool",
					Detail:  fmt.Sprintf("Agent tool '%s' calls eval()/exec()/compile() on line %d — the LLM can run arbitrary Python through this tool", span.name, j+1),
					RawLine: bodyTrimmed,
					Source:  "static_analysis",
				})
			case reFileWriteDynamic.MatchString(lines[j]):
				evidence = append(evidence, sandbox.Evidence{
					Label:   "Unscoped file write in tool",
					Detail:  fmt.Sprintf("Agent tool '%s' opens a parameter-derived path for writing on line %d — the LLM can write to any path it chooses through this tool", span.name, j+1),
					RawLine: bodyTrimmed,
					Source:  "static_analysis",
				})
			}
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Over-privileged agent tool — unscoped code execution or file write",
		Description: "An agent-callable tool (function_tool/mcp.tool/tool) grants the LLM an unscoped capability: arbitrary shell execution, dynamic code evaluation, or file writes to a caller-chosen path. If the LLM is tricked via prompt injection into misusing this tool, the capability has no boundary to contain the damage.",
		Severity:    "critical",
		ScoreImpact: -30,
		Evidence:    evidence,
		FixHint:     "Scope the capability before exposing it as a tool. For file writes, resolve the path with os.path.realpath() and verify it stays inside a fixed allow-listed directory before opening. For shell/subprocess calls, replace free-form commands with a fixed allow-list of permitted subcommands passed as a list (never shell=True). Replace eval()/exec()/compile() with a safe, restricted parser for the specific input format you actually need.",
	}, true
}

func detectToolDescriptionMismatch(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for _, span := range findToolFunctionSpans(lines) {
		docstring := extractDocstring(lines, span.defLine)
		if docstring == "" || !reReadOnlyClaim.MatchString(docstring) {
			continue
		}
		for j := span.bodyStart; j < span.bodyEnd; j++ {
			bodyTrimmed := strings.TrimSpace(lines[j])
			if bodyTrimmed == "" || strings.HasPrefix(bodyTrimmed, "#") {
				continue
			}
			if reMutatingPrimitive.MatchString(lines[j]) {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "Tool description mismatch",
					Detail:  fmt.Sprintf("Agent tool '%s' is documented as read-only but calls a mutating operation on line %d — the agent may invoke this tool expecting it to be safe", span.name, j+1),
					RawLine: bodyTrimmed,
					Source:  "static_analysis",
				})
				break // one finding per function
			}
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Tool description mismatch — docstring implies read-only, body mutates",
		Description: "An agent tool's docstring uses read-only language (fetch/lookup/get/query) but its implementation performs a mutating or destructive operation (delete, write, update). An agent choosing tools based on their description may invoke this expecting a safe, side-effect-free read.",
		Severity:    "warning",
		ScoreImpact: -15,
		Evidence:    evidence,
		FixHint:     "Either update the docstring to accurately describe the mutating behavior (e.g. 'Deletes the user's cached profile and returns the prior value'), or split the tool into a clearly-named read path and a separately-named, separately-described write/delete path so the agent's tool-selection signal is accurate.",
	}, true
}

func detectUnrestrictedOpenAIToolSchema(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for i := 0; i < len(lines); i++ {
		if !reToolsListOpen.MatchString(lines[i]) {
			continue
		}
		depth := strings.Count(lines[i], "[") - strings.Count(lines[i], "]") +
			strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
		end := i
		for j := i + 1; j < len(lines) && depth > 0 && j < i+200; j++ {
			end = j
			depth += strings.Count(lines[j], "[") - strings.Count(lines[j], "]")
			depth += strings.Count(lines[j], "{") - strings.Count(lines[j], "}")
		}
		for j := i; j <= end && j < len(lines); j++ {
			if !reRiskyParamName.MatchString(lines[j]) {
				continue
			}
			hasEnum := false
			for k := j; k <= end && k < j+6 && k < len(lines); k++ {
				if reEnumPresent.MatchString(lines[k]) {
					hasEnum = true
					break
				}
			}
			if !hasEnum {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "Unconstrained tool parameter",
					Detail:  fmt.Sprintf("OpenAI tool schema parameter on line %d has no \"enum\" constraint — the LLM can pass any value", j+1),
					RawLine: strings.TrimSpace(lines[j]),
					Source:  "static_analysis",
				})
			}
		}
		i = end // resume scanning after this tools=[...] block
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Unrestricted OpenAI tool schema — risky parameter with no enum constraint",
		Description: "A raw OpenAI function-calling tool schema defines a parameter named like a command, path, or code field with no \"enum\" constraint. The JSON schema is what actually constrains what the LLM can pass to your handler — an unconstrained string on a risky-named field gives the LLM a free-form value with no guardrail, regardless of how the handler itself is implemented.",
		Severity:    "warning",
		ScoreImpact: -15,
		Evidence:    evidence,
		FixHint:     "Add an \"enum\" array listing the specific allowed values for this parameter, or split it into a closed set of named sub-tools instead of a free-form string.",
	}, true
}

func detectMissingDocstring(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		m := reFuncDef.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		funcName := m[1]
		// Skip private / dunder helpers — only public tool functions matter.
		if strings.HasPrefix(funcName, "_") {
			continue
		}
		// Look at the next non-blank, non-comment line for a docstring.
		hasDoc := false
		for j := i + 1; j < len(lines) && j <= i+10; j++ {
			next := strings.TrimSpace(lines[j])
			if next == "" || strings.HasPrefix(next, "#") || strings.HasPrefix(next, "//") {
				continue // skip blank lines and inline comments before the docstring
			}
			if strings.HasPrefix(next, `"""`) || strings.HasPrefix(next, `'''`) {
				hasDoc = true
			}
			break
		}
		if !hasDoc {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "No docstring",
				Detail:  fmt.Sprintf("'%s' on line %d has no docstring — the agent cannot understand what this tool does or how to call it", funcName, i+1),
				RawLine: trimmed,
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Missing tool docstring — agent cannot understand tool capabilities",
		Description: "Tool functions lack docstrings. The agent runtime uses docstrings to understand what each tool does, what parameters it expects, and when to invoke it. Missing docstrings cause hallucinated usage or the tool being ignored entirely.",
		Severity:    "warning",
		ScoreImpact: -10,
		Evidence:    evidence,
		FixHint:     "Insert a docstring as the FIRST statement of the flagged function body ONLY. Do NOT delete, move, or modify ANY other code — not imports, not other functions, not class definitions, not module-level code. The entire file must remain intact except for the single inserted docstring. Example — only this line changes:\ndef ask(query: str) -> str:\n    # insert docstring here as first line of body\n    \"\"\"Ask the model a question and return its response.\"\"\"\n    # rest of function body unchanged",
	}, true
}

func detectUnboundedResponse(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, "return ") {
			continue
		}
		if !reUnboundedReturn.MatchString(line) {
			continue
		}
		// Allow if a slice or truncation is already applied on the same line.
		if strings.Contains(line, "[:") || strings.Contains(line, "truncat") || strings.Contains(line, "[:MAX") {
			continue
		}
		evidence = append(evidence, sandbox.Evidence{
			Label:   "Unbounded output",
			Detail:  fmt.Sprintf("Line %d returns a full response body or file read with no size limit — could push megabytes into agent context", i+1),
			RawLine: trimmed,
			Source:  "static_analysis",
		})
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Unbounded tool output — can overflow agent context window",
		Description: "The tool returns full HTTP response bodies or file contents without a size cap. Large responses consume the agent's entire context window, causing failures and spiking inference costs.",
		Severity:    "warning",
		ScoreImpact: -15,
		Evidence:    evidence,
		FixHint:     "Add a maximum character limit before returning to the agent. Example:\nMAX_OUTPUT = 4096\ntext = resp.text[:MAX_OUTPUT]\nif len(resp.text) > MAX_OUTPUT:\n    text += '\\n...[truncated]'\nreturn text\nChoose a limit appropriate to your agent's context window (2000–8000 chars is typical for a tool response).",
	}, true
}

func detectPromptInjectionRisk(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence

	// Track per-function: does it make a network call before returning raw content?
	type funcState struct {
		name       string
		hasNetwork bool
	}
	var cur funcState

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if m := reFuncDef.FindStringSubmatch(trimmed); m != nil {
			cur = funcState{name: m[1]}
			continue
		}

		if reHTTPCallOpen.MatchString(line) || reNetworkCall.MatchString(line) {
			cur.hasNetwork = true
		}

		// Flag when a function that made a network call returns raw text/content
		// without extracting a specific field — attacker-controlled server can inject.
		if cur.hasNetwork && strings.Contains(trimmed, "return ") {
			rawReturn := strings.Contains(line, ".text") ||
				strings.Contains(line, ".content") ||
				(strings.Contains(line, "resp.json()") && !strings.Contains(line, "resp.json()["))
			if rawReturn {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "Unfiltered external content",
					Detail:  fmt.Sprintf("'%s' returns raw HTTP response content on line %d — a malicious server response could inject instructions into the agent", cur.name, i+1),
					RawLine: trimmed,
					Source:  "static_analysis",
				})
				cur.hasNetwork = false // one finding per function
			}
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Prompt injection risk — unfiltered external content returned to agent",
		Description: "The tool returns raw content fetched from external sources directly to the agent. A compromised or malicious server can embed instructions like 'Ignore previous instructions' in its response, hijacking the agent's behavior.",
		Severity:    "critical",
		ScoreImpact: -25,
		Evidence:    evidence,
		FixHint:     "Extract only the specific data fields you need instead of returning raw response bodies. If you must return free-form text, sanitize it first by stripping HTML tags and wrapping the content with a clear boundary marker so the agent treats it as data, not instructions. Example:\nreturn f'[TOOL RESULT]\\n{extract_text(resp.text)[:2000]}\\n[END TOOL RESULT]'",
	}, true
}

func detectHardcodedSecret(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		m := reSecretAssign.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val := m[1]
		// Skip URLs, obvious placeholders, and env-var references.
		lower := strings.ToLower(val)
		if strings.HasPrefix(val, "http") ||
			strings.Contains(lower, "placeholder") ||
			strings.Contains(lower, "your-") ||
			strings.Contains(lower, "example") ||
			strings.Contains(val, "<") ||
			strings.Contains(val, "environ") {
			continue
		}
		evidence = append(evidence, sandbox.Evidence{
			Label:   "Hardcoded secret",
			Detail:  fmt.Sprintf("Credential variable assigned a string literal on line %d", i+1),
			RawLine: strings.TrimSpace(line),
			Source:  "static_analysis",
		})
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Hardcoded credentials — secret exposed in source",
		Description: "The tool contains a hardcoded API key or secret. Anyone with access to the source, container image, or logs can extract it.",
		Severity:    "critical",
		ScoreImpact: -30,
		Evidence:    evidence,
		FixHint:     "Move the secret to an environment variable. Replace the hardcoded value with os.environ.get('VAR_NAME', ''). Use a lazy check INSIDE the function that uses it — never assert or raise at module level, as that prevents the tool from loading in sandboxed environments. Example: `API_KEY = os.environ.get('OPENAI_API_KEY', '')` at module level, then inside the function: `if not API_KEY: return 'Error: OPENAI_API_KEY is not configured'`. Do NOT commit the actual value anywhere.",
	}, true
}

func detectShellInjection(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if reOsSystem.MatchString(line) {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Shell execution",
				Detail:  fmt.Sprintf("os.system() on line %d runs a shell command — injectable if any argument comes from user input", i+1),
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
			continue
		}
		if reSubprocess.MatchString(line) {
			hasShellTrue := strings.Contains(line, "shell=True")
			if !hasShellTrue {
				depth := strings.Count(line, "(") - strings.Count(line, ")")
				for j := i + 1; j < len(lines) && depth > 0 && j < i+15; j++ {
					if strings.Contains(lines[j], "shell=True") {
						hasShellTrue = true
						break
					}
					depth += strings.Count(lines[j], "(") - strings.Count(lines[j], ")")
				}
			}
			if hasShellTrue {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "Shell injection risk",
					Detail:  fmt.Sprintf("subprocess call with shell=True on line %d — user-controlled input passed to a shell is injectable", i+1),
					RawLine: strings.TrimSpace(line),
					Source:  "static_analysis",
				})
			}
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Shell injection — user input executed as shell command",
		Description: "The tool passes potentially user-controlled data to a shell. An attacker can inject shell metacharacters to run arbitrary commands.",
		Severity:    "critical",
		ScoreImpact: -30,
		Evidence:    evidence,
		FixHint:     "Replace os.system() with subprocess.run(cmd_list, shell=False) where cmd_list is a Python list. Never set shell=True with user-controlled input. Example: replace os.system(f'grep {q} file') with subprocess.run(['grep', q, 'file'], shell=False, capture_output=True).",
	}, true
}

func detectInsecureDeserialization(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if rePickle.MatchString(line) {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Unsafe pickle",
				Detail:  fmt.Sprintf("pickle.loads() on line %d can execute arbitrary code when deserializing untrusted data", i+1),
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
		}
		if reYamlLoad.MatchString(line) && !strings.Contains(line, "SafeLoader") && !strings.Contains(line, "safe_load") {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Unsafe YAML load",
				Detail:  fmt.Sprintf("yaml.load() without SafeLoader on line %d can instantiate arbitrary Python objects", i+1),
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Insecure deserialization — arbitrary code execution risk",
		Description: "The tool deserializes data with unsafe methods. Deserializing attacker-controlled pickle or YAML can execute arbitrary Python.",
		Severity:    "critical",
		ScoreImpact: -30,
		Evidence:    evidence,
		FixHint:     "Replace pickle.loads() with json.loads() where possible. Replace yaml.load(data) with yaml.safe_load(data). If pickle is required, validate the data source is fully trusted and use HMAC signing to verify integrity before deserializing.",
	}, true
}

func detectMissingEnvCheck(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if m := reBracketEnv.FindStringSubmatch(line); m != nil {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Unchecked env var",
				Detail:  fmt.Sprintf("os.environ[\"%s\"] on line %d raises KeyError if the variable is unset, crashing the agent", m[1], i+1),
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Missing environment variable validation — agent crash risk",
		Description: "The tool reads environment variables with os.environ[] which raises KeyError if the variable is missing, terminating the agent run with no useful error.",
		Severity:    "warning",
		ScoreImpact: -15,
		Evidence:    evidence,
		FixHint:     "Replace os.environ[\"KEY\"] with os.environ.get(\"KEY\") and validate at startup. Example:\nAPI_KEY = os.environ.get(\"OPENAI_API_KEY\")\nif not API_KEY:\n    raise ValueError(\"OPENAI_API_KEY environment variable is required\")\nPlace this at module level so the error is immediate and clear when the tool is loaded.",
	}, true
}

// detectMaliciousPackages cross-checks imported third-party package names
// against a static, offline deny-list of documented PyPI typosquats. Unlike
// detectMissingDependency (which flags undeclared deps), this flags imports
// that match a known-malicious or impersonating package name — the risk is
// the import itself, not whether it's declared. Deliberately does NOT route
// through ExtractImports()/knownThirdParty: those exist to map known-good
// framework imports to pip names, so a typosquat name (by definition absent
// from that map) would never surface if filtered through it first.
func detectMaliciousPackages(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	seen := map[string]bool{}
	for _, m := range reImport.FindAllStringSubmatch(src, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if dot := strings.Index(name, "."); dot != -1 {
			name = name[:dot]
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			continue
		}
		entry, isTyposquat := typosquatPackages[lower]
		if !isTyposquat {
			continue
		}
		seen[lower] = true
		evidence = append(evidence, sandbox.Evidence{
			Label:   "Known typosquatted package",
			Detail:  fmt.Sprintf("import '%s' matches a documented PyPI typosquat of '%s' — %s", name, entry.LegitimatePackage, entry.Note),
			RawLine: "import " + name,
			Source:  "static_analysis",
		})
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Malicious or typosquatted dependency detected",
		Description: "The tool imports a package name matching a documented PyPI supply-chain attack — typically a deliberate misspelling of a popular library used to trick developers into installing malware-laden code.",
		Severity:    "critical",
		ScoreImpact: -30,
		Evidence:    evidence,
		FixHint:     "Verify the exact package name being imported. If this is a typo, replace it with the legitimate package shown in the evidence and update any requirements file accordingly. If the import is intentional and the name is correct, double-check it against the official PyPI project page before assuming this is a false positive.",
	}, true
}

func analyzeGo(src string) []sandbox.Candidate {
	var candidates []sandbox.Candidate
	if c, ok := detectGoMissingTimeout(src); ok {
		candidates = append(candidates, c)
	}
	if c, ok := detectGoUnauthorizedNetwork(src); ok {
		candidates = append(candidates, c)
	}
	if c, ok := detectGoHardcodedSecret(src); ok {
		candidates = append(candidates, c)
	}
	if c, ok := detectGoUnsafeExec(src); ok {
		candidates = append(candidates, c)
	}
	return candidates
}

func detectMissingTimeout(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if m := reURLOpen.FindStringSubmatch(line); m != nil {
			if !strings.Contains(m[1], "timeout=") {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "No timeout",
					Detail:  fmt.Sprintf("urlopen() called without timeout= on line %d", i+1),
					RawLine: strings.TrimSpace(line),
					Source:  "static_analysis",
				})
			}
		}
		if m := reHTTPCallOpen.FindStringSubmatch(line); m != nil {
			// Scan ahead through the call (track paren depth) to find timeout=.
			hasTimeout := strings.Contains(line, "timeout=")
			if !hasTimeout {
				depth := strings.Count(line, "(") - strings.Count(line, ")")
				for j := i + 1; j < len(lines) && depth > 0 && j < i+30; j++ {
					if strings.Contains(lines[j], "timeout=") {
						hasTimeout = true
						break
					}
					depth += strings.Count(lines[j], "(") - strings.Count(lines[j], ")")
				}
			}
			if !hasTimeout {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "No timeout",
					Detail:  fmt.Sprintf("requests.%s() called without timeout= on line %d", m[1], i+1),
					RawLine: strings.TrimSpace(line),
					Source:  "static_analysis",
				})
			}
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "No timeout handling — tool can hang agent indefinitely",
		Description: "The tool has no timeout on network or IO operations. A slow or degraded dependency will stall the agent with no retry or fallback.",
		Severity:    "critical",
		ScoreImpact: -20,
		Evidence:    evidence,
	}, true
}

func detectUnauthorizedNetwork(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for i, line := range lines {
		if reNetworkCall.MatchString(line) {
			if hasOutboundDecl(lines, i) {
				continue
			}
			detail := fmt.Sprintf("Outbound network call on line %d is not declared in tool metadata", i+1)
			if name := mcpToolNameAt(lines, i); name != "" {
				detail = fmt.Sprintf("Outbound network call on line %d, inside MCP tool '%s', is not declared in tool metadata — agents that load this MCP server cannot see what data it exfiltrates", i+1, name)
			}
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Undeclared outbound call",
				Detail:  detail,
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Unauthorized network calls — tool may exfiltrate data",
		Description: "The tool makes outbound network connections that are not declared in its metadata. The network call is intentional and must remain — it just needs to be documented so the agent runtime can enforce least-privilege policy.",
		Severity:    "critical",
		ScoreImpact: -25,
		Evidence:    evidence,
		FixHint:     "Add a comment directly above the function signature that declares the outbound endpoint using this exact format: '# Outbound: api.example.com:443 — fetches alert data'. Use '#' for Python, '//' for Go/JS/TS. The network call itself MUST remain completely unchanged. Do not remove, stub, disable, or comment out any network code.",
	}, true
}

func detectMissingDependency(src, dir string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	seen := map[string]bool{}
	for _, m := range reImport.FindAllStringSubmatch(src, -1) {
		// m[1] is from "import X", m[2] is from "from X import"
		name := m[1]
		if name == "" {
			name = m[2]
		}
		// strip sub-package: "urllib.request" → "urllib"
		if dot := strings.Index(name, "."); dot != -1 {
			name = name[:dot]
		}
		if name == "" || stdlibModules[name] || IsLocalModule(dir, name) {
			continue
		}
		pipName := name
		if mapped, ok := knownThirdParty[name]; ok {
			pipName = mapped
		}
		if seen[pipName] {
			continue
		}
		// Skip if this specific package is already listed in any requirements file.
		if isDeclaredInRequirements(dir, pipName) || isDeclaredInRequirements(dir, name) {
			continue
		}
		seen[pipName] = true
		evidence = append(evidence, sandbox.Evidence{
			Label:   "Missing dependency",
			Detail:  fmt.Sprintf("import '%s' (pip: %s) is not declared in any requirements file", name, pipName),
			RawLine: "import " + name,
			Source:  "static_analysis",
		})
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Missing dependency declarations",
		Description: "The tool imports packages that are not declared in any requirements file, making deployment unpredictable.",
		Severity:    "warning",
		ScoreImpact: -10,
		Evidence:    evidence,
		FixHint:     "Add a requirements comment block at the very top of the file (before any imports). Use the pip package name shown in the evidence (e.g. 'openai-agents', not the import name 'agents'). Use exactly this format:\n# requirements:\n#   openai-agents\n#   requests\nOnly list packages shown in the evidence.",
	}, true
}

// hasOutboundDecl returns true if a network call at callLineIdx is already covered
// by an "// Outbound:" or "# Outbound:" declaration. It scans backwards to the
// nearest function signature, then continues through the doc comment block above it.
func hasOutboundDecl(lines []string, callLineIdx int) bool {
	for i := callLineIdx; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if strings.Contains(trimmed, "// Outbound:") || strings.Contains(trimmed, "# Outbound:") {
			return true
		}
		if strings.HasPrefix(trimmed, "func ") || strings.HasPrefix(trimmed, "def ") {
			// Continue scanning upward through the doc comment block above the signature.
			for j := i - 1; j >= 0; j-- {
				above := strings.TrimSpace(lines[j])
				if strings.Contains(above, "// Outbound:") || strings.Contains(above, "# Outbound:") {
					return true
				}
				// Stop once we leave the comment block.
				if above != "" && !strings.HasPrefix(above, "//") && !strings.HasPrefix(above, "#") {
					break
				}
			}
			return false
		}
	}
	return false
}

// mcpToolNameAt returns the function name if lineIdx falls within the nearest
// preceding function whose decorator is @mcp.tool(...), or "" otherwise.
// MCP servers are typically installed by other users/agents who trust the
// declared tool surface, making an undeclared network call inside an MCP
// tool a sharper trust violation than the same call in an ordinary script.
func mcpToolNameAt(lines []string, lineIdx int) string {
	for i := lineIdx; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		m := reFuncDef.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			above := strings.TrimSpace(lines[j])
			if above == "" {
				continue
			}
			if strings.HasPrefix(above, "@mcp.tool") {
				return m[1]
			}
			if !strings.HasPrefix(above, "@") {
				break
			}
		}
		return ""
	}
	return ""
}

// Go-specific detectors

func detectGoMissingTimeout(src string) (sandbox.Candidate, bool) {
	if !reGoNetImport.MatchString(src) {
		return sandbox.Candidate{}, false
	}
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		if m := reGoHTTPDefault.FindStringSubmatch(line); m != nil {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "No timeout",
				Detail:  fmt.Sprintf("http.%s() uses http.DefaultClient which has no timeout (line %d)", m[1], i+1),
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
		}
		// http.Client{} literal with no Timeout field
		if strings.Contains(line, "http.Client{") && !strings.Contains(line, "Timeout:") {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "No timeout",
				Detail:  fmt.Sprintf("http.Client created without Timeout field (line %d)", i+1),
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "No timeout handling — tool can hang agent indefinitely",
		Description: "The tool makes HTTP calls without a client timeout. A slow dependency will stall the agent.",
		Severity:    "critical",
		ScoreImpact: -20,
		Evidence:    evidence,
	}, true
}

func detectGoUnauthorizedNetwork(src string) (sandbox.Candidate, bool) {
	if !reGoNetImport.MatchString(src) {
		return sandbox.Candidate{}, false
	}
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for i, line := range lines {
		if reGoHTTPDefault.MatchString(line) ||
			strings.Contains(line, "http.NewRequest(") ||
			strings.Contains(line, "net.Dial(") ||
			strings.Contains(line, "net.DialTimeout(") {
			if hasOutboundDecl(lines, i) {
				continue
			}
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Undeclared outbound call",
				Detail:  fmt.Sprintf("Outbound network call on line %d is not declared in tool metadata", i+1),
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Unauthorized network calls — tool may exfiltrate data",
		Description: "The tool makes outbound network connections that are not declared in its metadata. The network call is intentional and must remain — it just needs to be documented so the agent runtime can enforce least-privilege policy.",
		Severity:    "critical",
		ScoreImpact: -25,
		Evidence:    evidence,
		FixHint:     "Add a comment directly above the function signature that declares the outbound endpoint using this exact format: '# Outbound: api.example.com:443 — fetches alert data'. Use '#' for Python, '//' for Go/JS/TS. The network call itself MUST remain completely unchanged. Do not remove, stub, disable, or comment out any network code.",
	}, true
}

func detectGoHardcodedSecret(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if m := reGoSecretAssign.FindStringSubmatch(line); m != nil {
			val := m[1]
			lower := strings.ToLower(val)
			if strings.HasPrefix(val, "http") || strings.Contains(lower, "placeholder") ||
				strings.Contains(lower, "your-") || strings.Contains(lower, "example") ||
				strings.Contains(val, "<") {
				continue
			}
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Hardcoded secret",
				Detail:  fmt.Sprintf("Credential variable assigned a string literal on line %d", i+1),
				RawLine: trimmed,
				Source:  "static_analysis",
			})
		} else if reGoSecretPrefix.MatchString(line) {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Hardcoded secret",
				Detail:  fmt.Sprintf("String literal matches a known API key prefix on line %d", i+1),
				RawLine: trimmed,
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Hardcoded credentials — secret exposed in source",
		Description: "The tool contains a hardcoded API key or secret. Anyone with access to the source can extract it.",
		Severity:    "critical",
		ScoreImpact: -30,
		Evidence:    evidence,
		FixHint:     "Move the secret to an environment variable and read it with os.Getenv(\"VAR_NAME\"). Never commit real credentials to source control.",
	}, true
}

func detectGoUnsafeExec(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if reGoExecCall.MatchString(line) {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Shell execution",
				Detail:  fmt.Sprintf("exec.Command / os.StartProcess on line %d — verify arguments are not user-controlled", i+1),
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Unsafe shell execution — possible command injection",
		Description: "The tool invokes exec.Command or os.StartProcess. If any argument originates from user or agent input, this is a command-injection vector.",
		Severity:    "critical",
		ScoreImpact: -25,
		Evidence:    evidence,
		FixHint:     "Never pass user-controlled data directly to exec.Command. Use an allowlist of permitted commands, or redesign the tool to avoid shell invocation entirely.",
	}, true
}

// ── JS / TS ──────────────────────────────────────────────────────────────────

func analyzeJS(src string) []sandbox.Candidate {
	var candidates []sandbox.Candidate
	for _, fn := range []func(string) (sandbox.Candidate, bool){
		detectJSHardcodedSecret,
		detectJSUnauthorizedNetwork,
		detectJSMissingTimeout,
		detectJSMissingErrorHandling,
	} {
		if c, ok := fn(src); ok {
			candidates = append(candidates, c)
		}
	}
	return candidates
}

func detectJSHardcodedSecret(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if m := reJSSecretAssign.FindStringSubmatch(line); m != nil {
			val := m[1]
			lower := strings.ToLower(val)
			if strings.HasPrefix(val, "http") || strings.Contains(lower, "placeholder") ||
				strings.Contains(lower, "your-") || strings.Contains(lower, "example") ||
				strings.Contains(val, "<") || strings.Contains(val, "${") {
				continue
			}
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Hardcoded secret",
				Detail:  fmt.Sprintf("Credential variable assigned a string literal on line %d", i+1),
				RawLine: trimmed,
				Source:  "static_analysis",
			})
		} else if reJSSecretPrefix.MatchString(line) {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Hardcoded secret",
				Detail:  fmt.Sprintf("String literal matches a known API key prefix on line %d", i+1),
				RawLine: trimmed,
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Hardcoded credentials — secret exposed in source",
		Description: "The tool contains a hardcoded API key or secret. Anyone with access to the source can extract it.",
		Severity:    "critical",
		ScoreImpact: -30,
		Evidence:    evidence,
		FixHint:     "Move the secret to an environment variable and read it with process.env.VAR_NAME. Never commit real credentials to source control.",
	}, true
}

func detectJSUnauthorizedNetwork(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if reJSFetch.MatchString(line) || reJSAxios.MatchString(line) || reJSNodeHTTP.MatchString(line) {
			if hasOutboundDecl(lines, i) {
				continue
			}
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Undeclared outbound call",
				Detail:  fmt.Sprintf("Outbound network call on line %d is not declared in tool metadata", i+1),
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Unauthorized network calls — tool may exfiltrate data",
		Description: "The tool makes outbound network connections not declared in its metadata.",
		Severity:    "critical",
		ScoreImpact: -25,
		Evidence:    evidence,
		FixHint:     "Add a comment directly above the function that declares the outbound endpoint: '// Outbound: api.example.com:443 — fetches data'. The network call itself must remain unchanged.",
	}, true
}

func detectJSMissingTimeout(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if reJSFetch.MatchString(line) {
			// Scan the call site and a small window for signal:/AbortSignal.timeout
			window := strings.Join(lines[i:min(i+5, len(lines))], " ")
			if !reJSAbortSignal.MatchString(window) {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "No timeout",
					Detail:  fmt.Sprintf("fetch() on line %d has no AbortSignal.timeout or signal: option", i+1),
					RawLine: strings.TrimSpace(line),
					Source:  "static_analysis",
				})
			}
		}
		if reJSAxios.MatchString(line) {
			window := strings.Join(lines[i:min(i+8, len(lines))], " ")
			if !reJSAxiosTimeout.MatchString(window) {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "No timeout",
					Detail:  fmt.Sprintf("axios call on line %d has no timeout: option", i+1),
					RawLine: strings.TrimSpace(line),
					Source:  "static_analysis",
				})
			}
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "No timeout handling — tool can hang agent indefinitely",
		Description: "Network calls have no timeout. A slow dependency will stall the agent with no fallback.",
		Severity:    "critical",
		ScoreImpact: -20,
		Evidence:    evidence,
		FixHint:     "For fetch: pass { signal: AbortSignal.timeout(5000) }. For axios: pass { timeout: 5000 }.",
	}, true
}

func detectJSMissingErrorHandling(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if reJSAwaitFetch.MatchString(line) {
			// Check for try { in the 10 lines before this one
			start := i - 10
			if start < 0 {
				start = 0
			}
			window := strings.Join(lines[start:i+1], " ")
			if !reJSCatchOrTry.MatchString(window) {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "No error handling",
					Detail:  fmt.Sprintf("await fetch() on line %d is not inside a try/catch block", i+1),
					RawLine: strings.TrimSpace(line),
					Source:  "static_analysis",
				})
			}
		} else if reJSFetch.MatchString(line) && !strings.Contains(line, "await") {
			// Promise-style: look for .catch( in the next 5 lines
			window := strings.Join(lines[i:min(i+6, len(lines))], " ")
			if !strings.Contains(window, ".catch(") {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "No error handling",
					Detail:  fmt.Sprintf("fetch() on line %d has no .catch() handler", i+1),
					RawLine: strings.TrimSpace(line),
					Source:  "static_analysis",
				})
			}
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Missing error handling on network calls",
		Description: "Network calls without error handling will crash the agent on any network failure.",
		Severity:    "warning",
		ScoreImpact: -10,
		Evidence:    evidence,
		FixHint:     "Wrap await fetch() in try/catch, or add .catch() to promise chains. Return a structured error to the agent instead of throwing.",
	}, true
}

// ── Ruby ─────────────────────────────────────────────────────────────────────

func analyzeRuby(src string) []sandbox.Candidate {
	var candidates []sandbox.Candidate
	for _, fn := range []func(string) (sandbox.Candidate, bool){
		detectRubyHardcodedSecret,
		detectRubyUnauthorizedNetwork,
		detectRubyMissingTimeout,
	} {
		if c, ok := fn(src); ok {
			candidates = append(candidates, c)
		}
	}
	return candidates
}

func detectRubyHardcodedSecret(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reRubySecretAssign.FindStringSubmatch(line); m != nil {
			val := m[1]
			lower := strings.ToLower(val)
			if strings.HasPrefix(val, "http") || strings.Contains(lower, "placeholder") ||
				strings.Contains(lower, "your-") || strings.Contains(lower, "example") ||
				strings.Contains(val, "<") || strings.Contains(val, "#{") {
				continue
			}
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Hardcoded secret",
				Detail:  fmt.Sprintf("Credential variable assigned a string literal on line %d", i+1),
				RawLine: trimmed,
				Source:  "static_analysis",
			})
		} else if reRubySecretPrefix.MatchString(line) {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Hardcoded secret",
				Detail:  fmt.Sprintf("String literal matches a known API key prefix on line %d", i+1),
				RawLine: trimmed,
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Hardcoded credentials — secret exposed in source",
		Description: "The tool contains a hardcoded API key or secret. Anyone with access to the source can extract it.",
		Severity:    "critical",
		ScoreImpact: -30,
		Evidence:    evidence,
		FixHint:     "Move the secret to an environment variable and read it with ENV['VAR_NAME']. Never commit real credentials to source control.",
	}, true
}

func detectRubyUnauthorizedNetwork(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if reRubyNetworkCall.MatchString(line) {
			if hasOutboundDecl(lines, i) {
				continue
			}
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Undeclared outbound call",
				Detail:  fmt.Sprintf("Outbound network call on line %d is not declared in tool metadata", i+1),
				RawLine: strings.TrimSpace(line),
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Unauthorized network calls — tool may exfiltrate data",
		Description: "The tool makes outbound network connections not declared in its metadata.",
		Severity:    "critical",
		ScoreImpact: -25,
		Evidence:    evidence,
		FixHint:     "Add a comment directly above the method that declares the outbound endpoint: '# Outbound: api.example.com:443 — fetches data'. The network call itself must remain unchanged.",
	}, true
}

func detectRubyMissingTimeout(src string) (sandbox.Candidate, bool) {
	lines := strings.Split(src, "\n")
	var evidence []sandbox.Evidence
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if reRubyHTTPNew.MatchString(line) {
			// Scan the next 15 lines for a timeout assignment
			end := i + 15
			if end > len(lines) {
				end = len(lines)
			}
			window := strings.Join(lines[i:end], "\n")
			if !reRubyTimeout.MatchString(window) {
				evidence = append(evidence, sandbox.Evidence{
					Label:   "No timeout",
					Detail:  fmt.Sprintf("Net::HTTP.new on line %d has no open_timeout or read_timeout", i+1),
					RawLine: strings.TrimSpace(line),
					Source:  "static_analysis",
				})
			}
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "No timeout handling — tool can hang agent indefinitely",
		Description: "Net::HTTP connections without timeouts will stall the agent if the remote server is slow.",
		Severity:    "critical",
		ScoreImpact: -20,
		Evidence:    evidence,
		FixHint:     "Set http.open_timeout = 5 and http.read_timeout = 10 immediately after Net::HTTP.new.",
	}, true
}

// ── Shell ─────────────────────────────────────────────────────────────────────

func analyzeShell(src string) []sandbox.Candidate {
	var candidates []sandbox.Candidate
	for _, fn := range []func(string) (sandbox.Candidate, bool){
		detectShellHardcodedSecret,
		detectShellUnsafeCurlWget,
		detectShellMissingSetE,
	} {
		if c, ok := fn(src); ok {
			candidates = append(candidates, c)
		}
	}
	return candidates
}

func detectShellHardcodedSecret(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := reShellSecretAssign.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val := m[1]
		// Skip env var references and empty placeholders
		if strings.Contains(val, "$") || strings.Contains(val, "your") ||
			strings.Contains(val, "example") || strings.Contains(val, "<") ||
			val == "" {
			continue
		}
		evidence = append(evidence, sandbox.Evidence{
			Label:   "Hardcoded secret",
			Detail:  fmt.Sprintf("Credential variable assigned a literal value on line %d", i+1),
			RawLine: trimmed,
			Source:  "static_analysis",
		})
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Hardcoded credentials — secret exposed in source",
		Description: "The shell script contains a hardcoded credential. Anyone with access to the source can extract it.",
		Severity:    "critical",
		ScoreImpact: -30,
		Evidence:    evidence,
		FixHint:     "Pass secrets via environment variables set outside the script. Never hard-code credentials in shell files.",
	}, true
}

func detectShellUnsafeCurlWget(src string) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if reShellCurlPipeSh.MatchString(line) {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "Pipe to shell",
				Detail:  fmt.Sprintf("curl/wget output piped directly to sh/bash on line %d — executes arbitrary remote code", i+1),
				RawLine: trimmed,
				Source:  "static_analysis",
			})
		} else if reShellCurlNoFail.MatchString(line) && !reShellCurlFail.MatchString(line) {
			evidence = append(evidence, sandbox.Evidence{
				Label:   "curl without --fail",
				Detail:  fmt.Sprintf("curl on line %d lacks -f/--fail; HTTP errors (4xx/5xx) are silently ignored", i+1),
				RawLine: trimmed,
				Source:  "static_analysis",
			})
		}
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Unsafe curl/wget usage",
		Description: "Unsafe HTTP download patterns: piping to shell executes arbitrary remote code; missing --fail silently swallows HTTP errors.",
		Severity:    "critical",
		ScoreImpact: -25,
		Evidence:    evidence,
		FixHint:     "Never pipe curl/wget to sh/bash. Always pass -f/--fail so HTTP errors abort the script. Download to a temp file, verify its contents, then execute.",
	}, true
}

func detectShellMissingSetE(src string) (sandbox.Candidate, bool) {
	if reShellSetE.MatchString(src) {
		return sandbox.Candidate{}, false
	}
	// Only flag scripts with actual commands (not just comments/blanks)
	hasCode := false
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "#") {
			hasCode = true
			break
		}
	}
	if !hasCode {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Missing error handling — script continues on failure",
		Description: "The script does not use 'set -e' or 'set -euo pipefail'. Any failed command is silently ignored and execution continues.",
		Severity:    "warning",
		ScoreImpact: -10,
		Evidence: []sandbox.Evidence{{
			Label:   "No set -e",
			Detail:  "Script has no 'set -e', 'set -euo pipefail', or 'set -o errexit' directive",
			RawLine: "",
			Source:  "static_analysis",
		}},
		FixHint: "Add 'set -euo pipefail' as the first non-comment line of the script to abort on any error.",
	}, true
}
