package analyzer

import "regexp"

// ── Python ───────────────────────────────────────────────────────────────────

var (
	// matches urlopen(args) — greedy-but-not-past-closing-paren
	reURLOpen = regexp.MustCompile(`urlopen\(([^)]*)\)`)

	// matches the opening of a requests/httpx/aiohttp call (multi-line safe)
	reHTTPCallOpen = regexp.MustCompile(`(?:requests|httpx|aiohttp)\.(get|post|put|delete|patch|head|options)\s*\(`)

	// top-level import statements: "import X" or "from X import ..."
	reImport = regexp.MustCompile(`(?m)^(?:import\s+(\S+)|from\s+(\S+)\s+import)`)

	// network-related call sites — includes method name so requests.post( matches
	reNetworkCall = regexp.MustCompile(
		`(?:urllib\.request\.urlopen|requests\.\w+|httpx\.\w+|aiohttp\.\w+|http\.client\.\w+|socket\.connect)\s*\(`,
	)

	// hardcoded secret: credential-like variable assigned a string literal
	reSecretAssign = regexp.MustCompile(
		`(?i)(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|token|auth[_-]?token|private[_-]?key|access[_-]?key)\s*=\s*["']([^"'\s]{6,})["']`,
	)

	// shell execution: os.system / os.popen
	reOsSystem = regexp.MustCompile(`os\.(system|popen)\s*\(`)

	// subprocess call opening (check for shell=True separately)
	reSubprocess = regexp.MustCompile(`subprocess\.(run|Popen|call|check_output|check_call)\s*\(`)

	// insecure deserialization
	rePickle   = regexp.MustCompile(`pickle\.(loads?)\s*\(`)
	reYamlLoad = regexp.MustCompile(`yaml\.load\s*\(`)

	// bracket env access raises KeyError if variable is unset
	reBracketEnv = regexp.MustCompile(`os\.environ\s*\[["']([^"']+)["']\]`)

	// function definition (public functions only — no leading underscore)
	reFuncDef = regexp.MustCompile(`^def\s+([a-zA-Z][a-zA-Z0-9_]*)\s*\(`)

	// return of raw response body or file read without slicing
	reUnboundedReturn = regexp.MustCompile(`return\s+.+(?:\.text|\.content|\.read\(\)|\.readlines\(\))`)

	// agent-tool-definition decorators: @function_tool, @mcp.tool(...), @tool(...)
	reAgentToolDecorator = regexp.MustCompile(`^@(?:function_tool|mcp\.tool|tool)\b`)

	// dynamic code execution primitives
	reEvalExecCompile = regexp.MustCompile(`\b(?:eval|exec|compile)\s*\(`)

	// open(<bare identifier>, "w"/"wb"/"a") — a parameter-derived path opened for writing
	reFileWriteDynamic = regexp.MustCompile(`open\s*\(\s*[a-zA-Z_]\w*\s*,\s*["'](?:w|wb|a)["']`)

	// docstring language implying a side-effect-free read
	reReadOnlyClaim = regexp.MustCompile(`(?i)\b(read[- ]?only|fetch(?:es)?|retriev(?:e|es)|look\s?up|gets?\s+(?:the|a|an|info)|query|queries)\b`)

	// body primitives that mutate or delete state, contradicting a read-only claim
	reMutatingPrimitive = regexp.MustCompile(`os\.remove\(|os\.unlink\(|subprocess\.|requests\.(?:post|put|delete|patch)\(|httpx\.(?:post|put|delete|patch)\(|\b(?:DELETE|DROP|UPDATE)\s+`)

	// call shapes across every language Probe scans that perform a real-world
	// side effect — network write, subprocess, filesystem delete, destructive
	// SQL — independent of any docstring claim. Broader than reMutatingPrimitive
	// (which is scoped to the read-only-docstring-mismatch check): also covers
	// Go's net/http POST helpers, JS fetch/axios write verbs, and Ruby's
	// Net::HTTP write calls, since a mutating tool can be written in any
	// language Probe supports sandboxing for. Deliberately anchored to
	// recognizable HTTP-client/library call shapes rather than a bare
	// ".post("/".delete(" — that would false-positive on ordinary local
	// list/dict/collection methods unrelated to any real-world side effect.
	reMutatingOperation = regexp.MustCompile(
		`os\.remove\(|os\.unlink\(|subprocess\.|` +
			`requests\.(?:post|put|delete|patch)\(|httpx\.(?:post|put|delete|patch)\(|` +
			`\b(?:DELETE|DROP|UPDATE)\s+|` +
			`http\.Post\(|http\.PostForm\(|http\.NewRequest\(\s*"(?:POST|PUT|DELETE|PATCH)"|` +
			`axios\.(?:post|put|delete|patch)\(|fetch\([^)]*method:\s*["'](?:POST|PUT|DELETE|PATCH)["']|` +
			`Net::HTTP\.(?:post|put|delete|patch)`,
	)

	// opening of a raw OpenAI function-calling tools=[...] schema literal
	reToolsListOpen = regexp.MustCompile(`tools\s*=\s*\[`)

	// JSON schema property name suggesting a command/path/code parameter
	reRiskyParamName = regexp.MustCompile(`"(?:command|cmd|shell_cmd|path|filepath|file_path|code|script)"\s*:\s*\{`)

	// presence of an "enum" constraint on a JSON schema property
	reEnumPresent = regexp.MustCompile(`"enum"\s*:`)
)

// ── Go ───────────────────────────────────────────────────────────────────────

var (
	// http.Get/Post/Head/Do calls using the default client (no timeout)
	reGoHTTPDefault = regexp.MustCompile(`http\.(Get|Post|Head|Do)\(`)
	// net/http or net imports
	reGoNetImport = regexp.MustCompile(`"net/http"|"net"`)

	reGoSecretAssign = regexp.MustCompile(
		`(?i)(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|token|auth[_-]?token|private[_-]?key|access[_-]?key)\s*(?::?=|=)\s*"([^"\s]{6,})"`,
	)
	reGoSecretPrefix = regexp.MustCompile(`"(sk-|ghp_|ghs_|xoxb-|xoxp-|AKIA)[^"\s]{6,}"`)
	reGoExecCall     = regexp.MustCompile(`exec\.Command\(|os\.StartProcess\(`)
)

// ── JS / TS ──────────────────────────────────────────────────────────────────

var (
	reJSSecretAssign = regexp.MustCompile(
		`(?i)(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|token|auth[_-]?token|private[_-]?key|access[_-]?key)\s*[=:]\s*['"]([^'"\s]{6,})['"]`,
	)
	reJSSecretPrefix = regexp.MustCompile(`['"](?:sk-|ghp_|ghs_|xoxb-|xoxp-|AKIA)[^'"\s]{6,}['"]`)
	reJSFetch        = regexp.MustCompile(`\bfetch\s*\(`)
	reJSAxios        = regexp.MustCompile(`\baxios\s*\.?\s*(?:get|post|put|delete|patch|request)\s*\(|\baxios\s*\(`)
	reJSNodeHTTP     = regexp.MustCompile(`require\s*\(\s*['"]https?['"]\s*\)`)
	reJSAbortSignal  = regexp.MustCompile(`AbortSignal\.timeout\(|signal\s*:`)
	reJSAxiosTimeout = regexp.MustCompile(`timeout\s*:`)
	reJSAwaitFetch   = regexp.MustCompile(`\bawait\s+fetch\s*\(`)
	reJSCatchOrTry   = regexp.MustCompile(`\.catch\s*\(|try\s*\{`)
)

// ── Ruby ─────────────────────────────────────────────────────────────────────

var (
	reRubySecretAssign = regexp.MustCompile(
		`(?i)(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|token|auth[_-]?token|private[_-]?key|access[_-]?key)\s*=\s*['"]([^'"\s]{6,})['"]`,
	)
	reRubySecretPrefix = regexp.MustCompile(`['"](?:sk-|ghp_|ghs_|xoxb-|xoxp-|AKIA)[^'"\s]{6,}['"]`)
	reRubyNetworkCall  = regexp.MustCompile(`Net::HTTP\.|open\(["']?https?|URI\.open\(|RestClient\.|HTTParty\.|Faraday\.new\(|::HTTP\.get\(|::HTTP\.post\(`)
	reRubyHTTPNew      = regexp.MustCompile(`Net::HTTP\.new\(`)
	reRubyTimeout      = regexp.MustCompile(`\.open_timeout\s*=|\.read_timeout\s*=|\.write_timeout\s*=`)
)

// ── Shell ────────────────────────────────────────────────────────────────────

var (
	reShellSecretAssign = regexp.MustCompile(
		`(?i)(?:API_KEY|SECRET(?:_KEY)?|PASSWORD|PASSWD|TOKEN|AUTH_TOKEN|PRIVATE_KEY|ACCESS_KEY)\s*=\s*['"]?([^'"\s$(){}\[\]]{6,})['"]?`,
	)
	reShellCurlPipeSh = regexp.MustCompile(`curl\b[^|]*\|\s*(?:ba)?sh\b|wget\b[^|]*\|\s*(?:ba)?sh\b`)
	reShellCurlNoFail = regexp.MustCompile(`\bcurl\b`)
	reShellCurlFail   = regexp.MustCompile(`\bcurl\b.*(?:-f\b|--fail\b)`)
	reShellSetE       = regexp.MustCompile(`set\s+-[a-zA-Z]*e[a-zA-Z]*|set\s+-o\s+errexit`)
)
