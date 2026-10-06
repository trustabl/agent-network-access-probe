package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	term "github.com/charmbracelet/x/term"
	figure "github.com/common-nighthawk/go-figure"
	"github.com/spf13/cobra"
	"github.com/trustabl/agent-network-access-probe/internal/analyzer"
	"github.com/trustabl/agent-network-access-probe/internal/attestation"
	"github.com/trustabl/agent-network-access-probe/internal/cache"
	"github.com/trustabl/agent-network-access-probe/internal/class"
	"github.com/trustabl/agent-network-access-probe/internal/discover"
	"github.com/trustabl/agent-network-access-probe/internal/findings"
	"github.com/trustabl/agent-network-access-probe/internal/fixer"
	"github.com/trustabl/agent-network-access-probe/internal/llm"
	"github.com/trustabl/agent-network-access-probe/internal/policy"
	"github.com/trustabl/agent-network-access-probe/internal/profile"
	"github.com/trustabl/agent-network-access-probe/internal/sandbox"
)

var (
	styleAdded    = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))             // green
	styleRemoved  = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))             // red
	styleHunk     = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))             // cyan
	styleHeader   = lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true) // bright blue
	styleDim      = lipgloss.NewStyle().Faint(true)
	stylePrompt   = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true) // yellow
	styleAccept   = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)  // green
	styleReject   = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)  // red
	styleCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)  // bright red
	styleInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))            // bright cyan
)

func severityBadge(severity string) string {
	switch severity {
	case "critical":
		return styleCritical.Render("● CRITICAL")
	case "warning":
		return stylePrompt.Render("⚠ WARNING")
	default:
		return styleInfo.Render("ℹ INFO")
	}
}

func scoreBar(score int) string {
	const width = 20
	filled := min(score*width/100, width)
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func colorizeDiff(diff string) string {
	var b strings.Builder
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---"):
			b.WriteString(styleHeader.Render(line))
		case strings.HasPrefix(line, "+"):
			b.WriteString(styleAdded.Render(line))
		case strings.HasPrefix(line, "-"):
			b.WriteString(styleRemoved.Render(line))
		case strings.HasPrefix(line, "@@"):
			b.WriteString(styleHunk.Render(line))
		default:
			b.WriteString(styleDim.Render(line))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// denyFinding builds one Candidate covering every denied destination a tool
// reached — one Evidence entry per host, not one Candidate per host, so a
// tool hitting several denied destinations doesn't spam the finding list.
func denyFinding(denied []policy.AllowedEndpoint) sandbox.Candidate {
	var evidence []sandbox.Evidence
	for _, ep := range denied {
		evidence = append(evidence, sandbox.Evidence{
			Label:  "Denied destination",
			Detail: fmt.Sprintf("%s:%d (%s) matches the deny list", ep.Host, ep.Port, ep.Protocol),
			Source: "deny_list",
		})
	}
	return sandbox.Candidate{
		Title:       "Observed egress to denied destination",
		Description: "The tool reached a destination on the deny list (built-in metadata/link-local protection, or a customer --deny-list entry). It is excluded from the generated policy draft and must not be allowed.",
		Severity:    "critical",
		ScoreImpact: -30,
		Evidence:    evidence,
		FixHint:     "This destination is blocklisted — do not add it to the tool's allow list. If this is unexpected, investigate why the tool is reaching a cloud metadata or link-local endpoint; that's a common SSRF/credential-theft pattern.",
	}
}

// notInOrgAllowFinding builds one Candidate covering every observed
// destination that isn't on the declared/platform allow list — one Evidence
// entry per host. Per the product spec's list-evaluation rules ("Observed −
// declared-allow → finding egress.not_in_org_allow — do not auto-add"),
// these are reported, not written into network_policies.draft.yaml.
func notInOrgAllowFinding(notInAllow []policy.AllowedEndpoint) sandbox.Candidate {
	var evidence []sandbox.Evidence
	for _, ep := range notInAllow {
		evidence = append(evidence, sandbox.Evidence{
			Label:  "Undeclared destination",
			Detail: fmt.Sprintf("%s:%d (%s) is not on the declared or platform allow list", ep.Host, ep.Port, ep.Protocol),
			Source: "egress.not_in_org_allow",
		})
	}
	return sandbox.Candidate{
		Title:       "Observed egress not on the declared allow list",
		Description: "The tool reached a destination that isn't in the supplied --allow-list or --platform-allow-list. It is excluded from the generated policy draft — an allow list, once supplied, is treated as the required source of truth, not just an addition to what was observed.",
		Severity:    "warning",
		ScoreImpact: -15,
		Evidence:    evidence,
		FixHint:     "If this destination is legitimate, add it to your --allow-list (or --platform-allow-list if it's a platform must-reach endpoint) so it's included in the draft on the next run.",
	}
}

// classSplitFinding reports hosts in the unioned class policy that aren't
// needed by every tool in the class — i.e. the union grants some tools
// reachability they never asked for, purely because they share a jail with
// a tool that does need it. Per Section 9 ("do not silently union into an
// over-broad policy"), this makes that trade-off visible rather than
// silent. Returns ok=false when every host is universally shared (no split
// candidate) — the common, expected case for most classes.
func classSplitFinding(hostTools map[string][]string, total int) (sandbox.Candidate, bool) {
	var evidence []sandbox.Evidence
	for host, tools := range hostTools {
		if len(tools) >= total {
			continue // needed by every tool — not a split candidate
		}
		evidence = append(evidence, sandbox.Evidence{
			Label:  "Non-universal destination",
			Detail: fmt.Sprintf("%s is needed by %d/%d tools (%s) — the rest gain reachability to it only because they share this class's jail", host, len(tools), total, strings.Join(tools, ", ")),
			Source: "class_split",
		})
	}
	if len(evidence) == 0 {
		return sandbox.Candidate{}, false
	}
	return sandbox.Candidate{
		Title:       "Class union grants some tools network access they don't individually need",
		Description: "This class's generated policy is the union of every tool's observed egress. Because all tools in a class share one jail, a tool can now reach destinations that only a different tool in the class actually needed — not silently merged without visibility, per the product's least-privilege design.",
		Severity:    "warning",
		ScoreImpact: -10,
		Evidence:    evidence,
		FixHint:     "If this is intentional (the tools are meant to share this jail), no action needed. If not, consider splitting this class into separate classes/jails so each tool's policy stays scoped to what it actually needs.",
	}, true
}

// sandboxSkipFinding builds the finding recorded when a tool's sandbox
// execution is skipped by default because analyzer.DetectsMutatingOperation
// found a call shape with a real-world side effect (harness safety rules —
// a refund tool must not be able to charge prod from a default Probe run).
func sandboxSkipFinding(evidence []sandbox.Evidence) sandbox.Candidate {
	return sandbox.Candidate{
		Title:       "Sandbox execution skipped — tool appears to perform an irreversible operation",
		Description: "This tool's code contains a call shape with a real-world side effect (a network write, subprocess call, filesystem delete, or destructive SQL). By default Probe does not execute such tools inside the sandbox, since an allowed destination could otherwise really be charged, deleted, or modified during a scan.",
		Severity:    "warning",
		ScoreImpact: -10,
		Evidence:    evidence,
		FixHint:     "Pass --allow-write-tools to run this tool for real inside the sandbox — ideally combined with --env-fixtures pointing at staging/test-mode credentials so the tool's real call lands on a non-production endpoint rather than prod.",
	}
}

// mergeCandidates adds static-analysis candidates that the sandbox didn't already find.
// Sandbox runtime evidence takes precedence; static analysis fills the gaps.
// src is the current source text — used to suppress findings that are already addressed.
func mergeCandidates(runtime, static []sandbox.Candidate, src, filePath string) []sandbox.Candidate {
	seen := map[string]bool{}

	var filtered []sandbox.Candidate
	for _, c := range runtime {
		if alreadyAddressed(c, src, filePath) {
			continue
		}
		seen[c.Title] = true
		filtered = append(filtered, c)
	}
	for _, c := range static {
		if !seen[c.Title] && !alreadyAddressed(c, src, filePath) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// hasDirectNetworkCall returns true if user code contains explicit HTTP calls
// (not just framework/SDK usage that internally makes network calls).
func hasDirectNetworkCall(src string) bool {
	for _, pat := range []string{"requests.", "httpx.", "urllib.request", "aiohttp.", "http.client."} {
		if strings.Contains(src, pat) {
			return true
		}
	}
	return false
}

// alreadyAddressed returns true when source code evidence shows the issue is handled,
// or when the finding is a false positive (e.g. crash in library code, not user code).
func alreadyAddressed(c sandbox.Candidate, src, filePath string) bool {
	switch c.Title {
	case "No error handling — tool crashes agent":
		return strings.Contains(src, "except Exception") ||
			strings.Contains(src, "except:") ||
			!hasDirectNetworkCall(src)
	case "Missing dependency declarations":
		if strings.Contains(src, "# requirements:") {
			return true
		}
		if analyzer.HasRequirementsFile(filepath.Dir(filePath)) {
			return true
		}
		// Suppress sandbox candidates where every missing module is a local package
		// (e.g. "No module named 'examples'" when examples/ is in the repo).
		if len(c.Evidence) > 0 {
			allLocal := true
			for _, e := range c.Evidence {
				if mod := missingModuleName(e.Detail); mod == "" || !analyzer.IsLocalModule(filepath.Dir(filePath), mod) {
					allLocal = false
					break
				}
			}
			if allLocal {
				return true
			}
		}
	case "Unauthorized network calls — tool may exfiltrate data":
		// Suppress if already declared, or if user code has no direct network calls
		// (blocked connection came from library internals, not user code).
		return strings.Contains(src, "# Outbound:") ||
			strings.Contains(src, "// Outbound:") ||
			!hasDirectNetworkCall(src)
	case "Hardcoded credentials — secret exposed in source":
		return strings.Contains(src, "os.environ.get")
	case "Missing environment variable validation — agent crash risk":
		return !strings.Contains(src, "os.environ[")
	}
	return false
}

// missingModuleName extracts the top-level module name from a sandbox
// ModuleNotFoundError detail string, e.g.:
//
//	"ModuleNotFoundError: No module named 'examples.tools'" → "examples"
func missingModuleName(detail string) string {
	_, after, ok := strings.Cut(detail, "No module named '")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(after, "'")
	// Strip sub-package: "examples.tools" → "examples"
	top, _, _ := strings.Cut(name, ".")
	return top
}

// isInfraLine returns true for OpenShell infrastructure log lines that carry no
// signal for the user — gateway events, OCSF policy setup, Landlock config, etc.
func isInfraLine(line string) bool {
	for _, tag := range []string{"[gateway]", "[OCSF ]", "[sandbox]"} {
		if strings.Contains(line, tag) {
			return true
		}
	}
	return false
}

func printSandboxOutput(result *sandbox.ScanResult, header, dim lipgloss.Style) {
	title := fmt.Sprintf("─── Sandbox output ──────────────────────── %dms", result.DurationMs)
	fmt.Fprintf(os.Stderr, "\n%s\n", header.Render(title))
	logs := strings.TrimSpace(result.Logs)
	if logs == "" {
		fmt.Fprintf(os.Stderr, "  %s\n", dim.Render("(no output)"))
	} else {
		var filtered []string
		for _, line := range strings.Split(logs, "\n") {
			if !isInfraLine(line) {
				filtered = append(filtered, line)
			}
		}
		if len(filtered) == 0 {
			fmt.Fprintf(os.Stderr, "  %s\n", dim.Render("(no tool output)"))
		} else {
			if len(filtered) > 50 {
				filtered = append(filtered[:50], "... (truncated)")
			}
			for _, line := range filtered {
				fmt.Fprintf(os.Stderr, "  %s\n", dim.Render(line))
			}
		}
	}
	fmt.Fprintf(os.Stderr, "  %s\n\n", dim.Render(
		fmt.Sprintf("%d runtime candidate(s) found", len(result.Candidates)),
	))
}

func printResult(r *fixer.Result) {
	fmt.Printf("Summary: %s\n\n", r.Summary)
	if strings.TrimSpace(r.Diff) == "" {
		fmt.Printf("%s\n\n", styleDim.Render("  (no changes generated)"))
		return
	}
	fmt.Print(colorizeDiff(r.Diff))
	fmt.Println()
}

func promptAction(stdin *bufio.Reader) string {
	hint := stylePrompt.Render("[a]ccept") + "  " +
		styleReject.Render("[r]eject") + "  " +
		styleDim.Render("[A]ccept all  [R]eject all  [q]uit") +
		" > "
	for {
		fmt.Print(hint)
		line, _ := stdin.ReadString('\n')
		choice := strings.TrimSpace(line)
		switch choice {
		case "a", "r", "A", "R", "q":
			return choice
		default:
			fmt.Println("  Unknown key. Use a, r, A, R, or q.")
		}
	}
}

func applyFix(r *fixer.Result, path string) {
	target := path
	if r.FixedPath != "" {
		target = r.FixedPath
	}
	if err := os.WriteFile(target, []byte(r.Fixed), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "  Error writing fix: %v\n", err)
		return
	}
	fmt.Printf("%s\n", styleAccept.Render("  ✓ Fix applied to "+target))
}

// spinErr runs fn in a goroutine while showing a spinner on stderr.
func spinErr(label string, fn func() error) error {
	type outcome struct{ err error }
	ch := make(chan outcome, 1)
	go func() { ch <- outcome{fn()} }()

	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	i, line := 0, ""
	for {
		select {
		case out := <-ch:
			fmt.Fprintf(os.Stderr, "\r%-*s\r", len(line)+1, "")
			icon := styleAccept.Render("✓")
			if out.err != nil {
				icon = styleReject.Render("✗")
			}
			fmt.Fprintf(os.Stderr, "  %s %s\n", icon, label)
			return out.err
		case <-ticker.C:
			line = fmt.Sprintf("  %s %s", frames[i%len(frames)], label)
			fmt.Fprintf(os.Stderr, "\r%s", line)
			i++
		}
	}
}

func generateWithSpinner(label string, fn func() (*fixer.Result, error)) (*fixer.Result, error) {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

	type outcome struct {
		r   *fixer.Result
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		r, err := fn()
		ch <- outcome{r, err}
	}()

	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	i := 0
	line := ""
	for {
		select {
		case out := <-ch:
			fmt.Fprintf(os.Stderr, "\r%-*s\r", len(line)+1, "")
			if out.err != nil {
				fmt.Fprintf(os.Stderr, "  %s %s\n", styleReject.Render("✗"), label)
			} else {
				fmt.Fprintf(os.Stderr, "  %s %s\n", styleAccept.Render("✓"), label)
			}
			return out.r, out.err
		case <-ticker.C:
			line = fmt.Sprintf("  %s %s", frames[i%len(frames)], label)
			fmt.Fprintf(os.Stderr, "\r%s", line)
			i++
		}
	}
}

// sessionEntry records the outcome of a single fix candidate.
type sessionEntry struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Action   string `json:"action"` // "accepted" | "rejected" | "error"
	Summary  string `json:"summary,omitempty"`
	Diff     string `json:"diff,omitempty"`
}

type sessionReport struct {
	Timestamp string         `json:"timestamp"`
	Source    string         `json:"source"`
	Entries   []sessionEntry `json:"entries"`
	Accepted  int            `json:"accepted"`
	Rejected  int            `json:"rejected"`
}

func writeSessionLog(report sessionReport, sourcePath string) {
	report.Timestamp = time.Now().UTC().Format(time.RFC3339)
	for _, e := range report.Entries {
		switch e.Action {
		case "accepted":
			report.Accepted++
		case "rejected":
			report.Rejected++
		}
	}

	logPath := sourcePath + "/autofix-session.json"
	data, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write session log: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", styleDim.Render("Session log written to "+logPath))

	// Write combined patch of all accepted fixes.
	var patch strings.Builder
	for _, e := range report.Entries {
		if e.Action == "accepted" && e.Diff != "" {
			patch.WriteString(e.Diff)
			patch.WriteString("\n")
		}
	}
	if patch.Len() > 0 {
		patchPath := sourcePath + "/autofix-session.patch"
		if err := os.WriteFile(patchPath, []byte(patch.String()), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not write patch file: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", styleDim.Render("Patch file written to "+patchPath))
		}
	}

	fmt.Fprintf(os.Stderr, "%s  %s  %s\n",
		styleAccept.Render(fmt.Sprintf("✓ %d accepted", report.Accepted)),
		styleReject.Render(fmt.Sprintf("✗ %d rejected", report.Rejected)),
		styleDim.Render(fmt.Sprintf("(%d total)", len(report.Entries))),
	)
}

func printBanner(sourcePath string, entrypoints []string, runner, baseImage, llmModel string) {
	img := baseImage
	if img == "" {
		img = "auto"
	}

	eps := strings.Join(entrypoints, "  ")
	switch {
	case len(eps) > 36:
		eps = eps[:36] + "…"
	case eps == "":
		eps = "auto-discover"
	}

	trim := func(s string) string {
		return strings.Join(strings.Split(strings.TrimRight(s, "\n"), "\n"), "\n")
	}

	brand := trim(figure.NewFigure("trustabl", "small", true).String())
	product := trim(figure.NewFigure("autofix", "slant", true).String())

	// Render left first so we can measure its height for the divider.
	left := lipgloss.NewStyle().
		Padding(1, 3).
		Render(
			styleDim.Render(brand) + "\n" +
				styleHeader.Render(product) + "\n" +
				styleDim.Render("  v"+version+"  ·  network egress → least-privilege OpenShell policy"),
		)

	const rightW = 46
	const kvValMax = 28 // max value width before truncation

	kv := func(label, val string) string {
		if len(val) > kvValMax {
			val = val[:kvValMax-1] + "…"
		}
		return fmt.Sprintf("  %-14s %s\n", label, styleHeader.Render(val))
	}
	kvLines := kv("Source:", sourcePath) +
		kv("Entrypoints:", eps) +
		kv("Runner:", runner+" · "+img) +
		kv("Model:", llmModel)

	// Height(n) sets the content area; Padding(1,…) adds 2 rendered rows on top.
	// lipgloss.Height counts \n chars (one less than visible lines), so using the
	// raw count as the content height makes the rendered right match the left exactly.
	rightContentH := lipgloss.Height(left)

	right := lipgloss.NewStyle().
		Width(rightW).
		Height(rightContentH).
		Padding(1, 3).
		BorderLeft(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("8")).
		Render(kvLines)

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Render(lipgloss.JoinHorizontal(lipgloss.Top, left, right))

	// The two-column layout only reads correctly when the terminal is at least as
	// wide as the rendered box. A narrower (or non-tty/piped) terminal wraps the
	// box mid-line and mangles the borders, so fall back to a single-column
	// layout — no side panel, no outer border — that fits any width.
	if w, _, err := term.GetSize(os.Stderr.Fd()); err != nil || w < lipgloss.Width(box) {
		fmt.Fprintf(os.Stderr, "\n%s\n%s\n", left, kvLines)
		return
	}

	fmt.Fprintf(os.Stderr, "\n%s\n\n", box)
}

func printAttestationCard(m *attestation.Manifest, header, accept, warn, reject, dim lipgloss.Style) {
	fmt.Fprintf(os.Stderr, "\n%s\n", header.Render("─── Behavioral Attestation ──────────────────────────────"))

	tools := strings.Join(m.Entrypoints, "  ")
	langs := strings.Join(m.LanguagesDetected, ", ")
	fmt.Fprintf(os.Stderr, "  %-12s %s  %s\n", "Tool(s):", tools, dim.Render("["+langs+"]"))

	scoreStyle := accept
	if m.ProductionReadinessScore < 90 {
		scoreStyle = warn
	}
	if m.ProductionReadinessScore < 70 {
		scoreStyle = reject
	}
	bar := scoreBar(m.ProductionReadinessScore)
	fmt.Fprintf(os.Stderr, "  %-12s %s  %s\n", "Score:", scoreStyle.Render(bar), scoreStyle.Render(fmt.Sprintf("%d / 100", m.ProductionReadinessScore)))

	if len(m.NetworkCalls) > 0 {
		fmt.Fprintln(os.Stderr)
		for i, ep := range m.NetworkCalls {
			label := "Outbound:"
			if i > 0 {
				label = ""
			}
			fmt.Fprintf(os.Stderr, "  %-12s %s:%d\n", label, ep.Host, ep.Port)
		}
	}

	fmt.Fprintln(os.Stderr)
	var parts []string
	if m.FindingsSummary.Critical > 0 {
		parts = append(parts, reject.Render(fmt.Sprintf("● %d critical", m.FindingsSummary.Critical)))
	}
	if m.FindingsSummary.Warning > 0 {
		parts = append(parts, warn.Render(fmt.Sprintf("⚠ %d warning", m.FindingsSummary.Warning)))
	}
	if m.FindingsSummary.Total == 0 {
		parts = append(parts, accept.Render("no issues found"))
	}
	fmt.Fprintf(os.Stderr, "  %-12s %s\n", "Findings:", strings.Join(parts, "  ·  "))

	if m.SourceHash != "" {
		short := m.SourceHash
		if len(short) > 16 {
			short = short[:16] + "..."
		}
		fmt.Fprintf(os.Stderr, "\n  %s\n", dim.Render("source:"+short+"  ✓ behavioral fingerprint"))
	}
	if m.SHA256 != "" {
		short := m.SHA256
		if len(short) > 16 {
			short = short[:16] + "..."
		}
		fmt.Fprintf(os.Stderr, "  %s\n", dim.Render("sha256:"+short+"  ✓ content-addressed"))
	}
	fmt.Fprintln(os.Stderr)
}

// version is set at build time via -ldflags "-X main.version=<value>".
var version = "dev"

// fileCandidates groups the merged (static + runtime) candidates found for
// one file, keyed by its absolute path.
type fileCandidates struct {
	filePath   string
	candidates []sandbox.Candidate
	harnessID  string // sandbox.ScanResult.SandboxID for this file's run; empty if static-only
	cacheHit   bool   // true when the sandbox result came from internal/cache instead of a fresh run
}

// postScanParams bundles everything runPostScan needs once static analysis
// and (optionally) the sandbox have already produced candidates — shared by
// both the single-source `--source` flow and the `--class` flow.
type postScanParams struct {
	// sourcePath doubles as the label used in the attestation/session report
	// and the directory autofix-policy.yaml / autofix-attestation.json /
	// session files are written into.
	sourcePath  string
	entrypoints []string
	// class is empty for a plain --source run; populated with the class name
	// for a --class run, so probe.profile.json can record it.
	class          string
	allCandidates  []sandbox.Candidate
	allFiles       []fileCandidates
	srcContents    map[string]string
	denyList       *policy.DenyList
	allowList      *policy.AllowList
	existingPolicy string
	noSign         bool
	llmModel       string
	llmURL         string
	llmAPIKey      string
	llmTimeout     time.Duration
	outputFmt      string
	autoAcceptAll  bool
	concurrency    int
}

// runPostScan generates the policy + attestation from candidates already
// collected, then (if any candidates were found) generates and reviews
// AI-powered fixes for each one. This is the tail shared by every `fix`
// invocation — single-source, repo-mode, and --class — once scanning is done.
func runPostScan(p postScanParams) error {
	sourcePath := p.sourcePath
	entrypoints := p.entrypoints
	class := p.class
	allCandidates := p.allCandidates
	allFiles := p.allFiles
	srcContents := p.srcContents
	denyList := p.denyList
	allowList := p.allowList
	existingPolicy := p.existingPolicy
	noSign := p.noSign
	llmModel := p.llmModel
	llmURL := p.llmURL
	llmAPIKey := p.llmAPIKey
	llmTimeout := p.llmTimeout
	outputFmt := p.outputFmt
	autoAcceptAll := p.autoAcceptAll
	concurrency := p.concurrency

	// Build per-tool profile inputs first (before Generate) so a deny-list or
	// not-in-allow-list hit found here becomes a finding included in both the
	// policy draft's candidate list and the profile — one evaluation pass,
	// not one per artifact. Iterates srcContents (every tool actually
	// scanned), not allFiles — allFiles only contains tools that produced
	// at least one other finding, so a clean tool with real egress but zero
	// prior findings would otherwise silently drop out of the grant set,
	// the per-tool egress table, and (with it) the grant-set hash — the
	// same undercounting bug already fixed for the class-split computation
	// below, surfacing here too since grant-set hash's whole purpose is
	// representing every declared class member, not just the ones with
	// findings.
	fileIdx := make(map[string]int, len(allFiles))
	for i, f := range allFiles {
		fileIdx[f.filePath] = i
	}
	paths := make([]string, 0, len(srcContents))
	for fp := range srcContents {
		paths = append(paths, fp)
	}
	sort.Strings(paths) // deterministic order regardless of map iteration

	toolInputs := make([]profile.ToolInput, 0, len(paths))
	for _, fp := range paths {
		src := srcContents[fp]
		var existingCands []sandbox.Candidate
		var harnessID string
		var cacheHit bool
		idx, known := fileIdx[fp]
		if known {
			existingCands = allFiles[idx].candidates
			harnessID = allFiles[idx].harnessID
			cacheHit = allFiles[idx].cacheHit
		}
		_, denied, notInAllow := policy.ExtractToolEndpoints(existingCands, src, denyList, allowList)
		fileCands := existingCands
		if len(denied) > 0 {
			finding := denyFinding(denied)
			fileCands = append(fileCands, finding)
			allCandidates = append(allCandidates, finding)
		}
		if len(notInAllow) > 0 {
			finding := notInOrgAllowFinding(notInAllow)
			fileCands = append(fileCands, finding)
			allCandidates = append(allCandidates, finding)
		}
		if known {
			allFiles[idx].candidates = fileCands
		} else if len(fileCands) > 0 {
			// A previously-clean tool just gained a deny/not-in-allow
			// finding — give it a real allFiles entry so it goes through
			// fix-generation like any other file with findings.
			allFiles = append(allFiles, fileCandidates{filePath: fp, candidates: fileCands})
		}
		toolInputs = append(toolInputs, profile.ToolInput{
			Path:       filepath.ToSlash(fp),
			Language:   attestation.ExtToLanguage(filepath.Ext(fp)),
			Candidates: fileCands,
			Src:        src,
			HarnessID:  harnessID,
			CacheHit:   cacheHit,
		})
	}

	// Class-split visibility: every tool in a --class run shares one jail,
	// so the union of all tools' egress becomes the policy applied to all of
	// them. A host not needed by every tool means the union silently handed
	// some tools reachability they never asked for — report it rather than
	// merge it away quietly (Section 9: "do not silently union into an
	// over-broad policy"). Computed over srcContents (every tool actually
	// scanned), not allFiles — allFiles only contains tools that produced at
	// least one other finding, so a clean tool with real egress but zero
	// findings would otherwise silently drop out of both the numerator and
	// the "needed by every tool" denominator, undercounting both sides.
	// Candidates are looked up per file where available (allFiles) purely to
	// let ExtractToolEndpoints also mine evidence-string URLs; a tool absent
	// from allFiles still gets its source-literal URLs picked up correctly
	// with a nil candidate list. Only meaningful for --class runs with more
	// than one tool; appended only to allCandidates (not any allFiles[i]),
	// so it counts toward the findings/score summary but is never sent
	// through AI fix-generation — there's no single source file to patch
	// for it.
	// classCandidates holds findings not attributable to a single file (so
	// far, only the class-split finding) — needed separately from
	// allCandidates so probe.findings.json can mark them file-less rather
	// than misattributing them to whichever file happened to be scanned.
	var classCandidates []sandbox.Candidate
	if class != "" && len(srcContents) > 1 {
		candByPath := make(map[string][]sandbox.Candidate, len(allFiles))
		for _, f := range allFiles {
			candByPath[f.filePath] = f.candidates
		}
		hostTools := map[string][]string{}
		for fp, src := range srcContents {
			allowedEps, _, _ := policy.ExtractToolEndpoints(candByPath[fp], src, denyList, allowList)
			for _, ep := range allowedEps {
				hostTools[ep.Host] = append(hostTools[ep.Host], fp)
			}
		}
		if finding, ok := classSplitFinding(hostTools, len(srcContents)); ok {
			allCandidates = append(allCandidates, finding)
			classCandidates = append(classCandidates, finding)
		}
	}

	// Always generate policy + attestation regardless of whether there are fixes.
	policyDoc := policy.Generate(allCandidates, srcContents, denyList, allowList)
	if err := policy.WritePolicy(policyDoc, sourcePath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write policy: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", styleDim.Render("Policy written to "+sourcePath+"/network_policies.draft.yaml (unsigned draft)"))
	}

	toolProfile := profile.Build(sourcePath, class, toolInputs, denyList, allowList)
	if err := profile.Write(toolProfile, sourcePath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write profile: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", styleDim.Render("Profile written to "+sourcePath+"/probe.profile.json"))
	}

	findingsReport := findings.Build(sourcePath, class, toolInputs, classCandidates)
	if err := findings.Write(findingsReport, sourcePath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write findings: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", styleDim.Render("Findings written to "+sourcePath+"/probe.findings.json"))
	}

	if existingPolicy != "" {
		gaps, err := policy.Diff(existingPolicy, policyDoc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: policy diff failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "\n%s\n", styleHeader.Render("─── Policy Gap Analysis ───────────────────────────────"))
			policy.PrintDiff(os.Stderr, gaps,
				func(s string) string { return styleReject.Render(s) },
				func(s string) string { return stylePrompt.Render(s) },
				func(s string) string { return styleAccept.Render(s) },
			)
			fmt.Fprintln(os.Stderr)
		}
	}

	manifest := attestation.Build(allCandidates, entrypoints, sourcePath, policyDoc)
	if err := attestation.Write(manifest, sourcePath, noSign); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write attestation: %v\n", err)
	} else {
		printAttestationCard(manifest, styleHeader, styleAccept, stylePrompt, styleReject, styleDim)
		fmt.Fprintf(os.Stderr, "%s\n", styleDim.Render("Attestation written to "+sourcePath+"/autofix-attestation.json"))
	}

	totalCandidates := len(allCandidates)
	if totalCandidates == 0 {
		fmt.Println("No issues found. Nothing to fix.")
		return nil
	}

	concLabel := ""
	if concurrency > 1 {
		concLabel = fmt.Sprintf(" · concurrency %d", concurrency)
	}
	// filesWithCandidates: allFiles now always includes clean (zero-finding)
	// tools too (needed to carry their harnessID/cacheHit through), so this
	// display line counts only files actually contributing a candidate —
	// otherwise it would overstate how many files fixes are being generated
	// across.
	filesWithCandidates := 0
	for _, f := range allFiles {
		if len(f.candidates) > 0 {
			filesWithCandidates++
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s\n\n",
		styleHeader.Render(fmt.Sprintf("Found %d candidate(s) across %d file(s) — generating fixes%s", totalCandidates, filesWithCandidates, concLabel)),
	)

	// Normalize bare host:port URLs (e.g. Ollama) to include /v1.
	resolvedURL := strings.TrimRight(llmURL, "/")
	if !strings.Contains(resolvedURL[strings.LastIndex(resolvedURL, ":")+1:], "/") {
		resolvedURL += "/v1"
	}

	client := &llm.Client{
		BaseURL: resolvedURL,
		APIKey:  llmAPIKey,
		Model:   llmModel,
		Timeout: llmTimeout,
	}

	if outputFmt == "json" {
		var results []*fixer.Result
		for _, f := range allFiles {
			for i, candidate := range f.candidates {
				fmt.Fprintf(os.Stderr, "[%d/%d] %s (%s)\n",
					i+1, len(f.candidates), candidate.Title, f.filePath)
				r, err := fixer.Fix(f.filePath, candidate, client)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
					continue
				}
				if rel, relErr := filepath.Rel(sourcePath, f.filePath); relErr == nil {
					r.FilePath = filepath.ToSlash(rel)
				} else {
					r.FilePath = filepath.ToSlash(f.filePath)
				}
				results = append(results, r)
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	// Phase 1: generate fixes chained per file so fix N builds on fix N-1
	// within the same file. Fixes across different files are independent.
	type pendingFix struct {
		result    *fixer.Result
		candidate sandbox.Candidate
		filePath  string
	}

	// Precompute the global candidate index offset for each file so display
	// labels ([N/total]) are stable regardless of goroutine scheduling order.
	startIdx := make([]int, len(allFiles))
	{
		running := 0
		for i, f := range allFiles {
			startIdx[i] = running + 1
			running += len(f.candidates)
		}
	}

	// Phase 1: fan-out across files (independent), sequential within each file
	// (chain-src guarantee). Each goroutine buffers per-candidate detail lines
	// and stores them for a post-wait flush. Completion lines (✓/✗ [N/M] ...)
	// print live as each file finishes, giving the user real-time progress.
	type fileFixResults struct {
		fixes []pendingFix
		buf   string // buffered per-candidate detail, flushed after all goroutines complete
	}
	fileResults := make([]fileFixResults, len(allFiles))

	// renderProgress prints (or reprints via \r) the progress bar for n/total files.
	// Must be called while holding progressMu.
	renderProgress := func(n, total int) {
		pct := 0
		if total > 0 {
			pct = n * 100 / total
		}
		const barWidth = 20
		filled := 0
		if total > 0 {
			filled = n * barWidth / total
		}
		bar := styleAccept.Render(strings.Repeat("█", filled)) +
			styleDim.Render(strings.Repeat("░", barWidth-filled))
		suffix := ""
		if n == total && total > 0 {
			suffix = "  " + styleAccept.Render("done")
		}
		fmt.Fprintf(os.Stderr, "\r  [%s]  %3d%%  %d/%d%s",
			bar, pct, n, total, suffix)
	}

	// progressMu serializes live progress output so lines never interleave.
	var (
		progressMu     sync.Mutex
		completedFiles int
	)

	// Print the initial 0% bar before any goroutine starts.
	progressMu.Lock()
	renderProgress(0, len(allFiles))
	progressMu.Unlock()

	genSem := make(chan struct{}, concurrency)
	var genWg sync.WaitGroup
	for i, f := range allFiles {
		genSem <- struct{}{}
		genWg.Add(1)
		go func(idx int, f fileCandidates, base int) {
			defer genWg.Done()
			defer func() { <-genSem }()

			start := time.Now()
			var buf strings.Builder
			var fixes []pendingFix
			var genErr error
			initialSrc, _ := os.ReadFile(f.filePath)
			chainSrc := string(initialSrc)

			for j, candidate := range f.candidates {
				globalN := base + j
				fmt.Fprintf(&buf, "\n  %s  %s  %s\n",
					severityBadge(candidate.Severity),
					styleHeader.Render(candidate.Title),
					styleDim.Render(fmt.Sprintf("[%d/%d] %s", globalN, totalCandidates, f.filePath)),
				)
				for _, e := range candidate.Evidence {
					fmt.Fprintf(&buf, "  %s  %s\n",
						styleDim.Render("["+e.Source+"]"),
						stylePrompt.Render(e.Label+": ")+e.Detail,
					)
				}

				src := chainSrc
				fp := f.filePath
				r, err := fixer.FixContent(fp, src, candidate, client)
				if err != nil {
					fmt.Fprintf(&buf, "  %s Error: %v\n", styleReject.Render("✗"), err)
					genErr = err
					continue
				}
				fmt.Fprintf(&buf, "  %s Generated fix\n", styleAccept.Render("✓"))
				if r.FixedPath == "" {
					chainSrc = r.Fixed
				}
				fixes = append(fixes, pendingFix{r, candidate, f.filePath})
			}

			elapsed := time.Since(start)
			fixWord := "fixes"
			if len(fixes) == 1 {
				fixWord = "fix"
			}
			icon := styleAccept.Render("✓")
			errSuffix := ""
			if genErr != nil && len(fixes) == 0 {
				icon = styleReject.Render("✗")
				errSuffix = styleDim.Render("  " + genErr.Error())
			}
			label := filepath.Base(filepath.Dir(f.filePath)) + "/" + filepath.Base(f.filePath)

			progressMu.Lock()
			completedFiles++
			n := completedFiles
			// Erase the current progress bar line, print completion line, then
			// reprint the updated bar — bar always stays on the bottom line.
			fmt.Fprintf(os.Stderr, "\r\033[K")
			fmt.Fprintf(os.Stderr, "  %s [%d/%d]  %-38s %d %s  %s%s\n",
				icon, n, len(allFiles), label,
				len(fixes), fixWord,
				styleDim.Render(fmt.Sprintf("%.1fs", elapsed.Seconds())),
				errSuffix,
			)
			renderProgress(n, len(allFiles))
			progressMu.Unlock()

			fileResults[idx] = fileFixResults{fixes: fixes, buf: buf.String()}
		}(i, f, startIdx[i])
	}
	genWg.Wait()

	// Move past the progress bar line, then flush per-candidate detail in file order.
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr)
	for _, fr := range fileResults {
		if fr.buf != "" {
			fmt.Fprint(os.Stderr, fr.buf)
		}
	}

	// Flatten in file order (deterministic for Phase 2 review).
	var pending []pendingFix
	for _, fr := range fileResults {
		pending = append(pending, fr.fixes...)
	}

	if len(pending) == 0 {
		return nil
	}

	// Phase 2: review one by one.
	// On reject, re-generate subsequent fixes for the same file from the
	// current accepted state — fixes for other files are unaffected.
	fmt.Fprintf(os.Stderr, "\n%s\n\n", styleHeader.Render("─── Review fixes ────────────────────────────────"))

	stdin := bufio.NewReader(os.Stdin)
	autoAccept := autoAcceptAll
	autoReject := false
	session := sessionReport{Source: sourcePath}

	// Track the last-accepted source per file for re-generation.
	acceptedSrcByFile := map[string]string{}
	for _, f := range allFiles {
		src, _ := os.ReadFile(f.filePath)
		acceptedSrcByFile[f.filePath] = string(src)
	}

	for i := 0; i < len(pending); i++ {
		p := pending[i]
		displayPath := p.filePath
		if p.result.FixedPath != "" {
			displayPath = p.result.FixedPath
		}
		fmt.Printf("\n%s  %s  %s\n",
			severityBadge(p.result.Candidate.Severity),
			styleHeader.Render(p.result.Candidate.Title),
			styleDim.Render(fmt.Sprintf("[%d/%d] %s", i+1, len(pending), displayPath)),
		)
		printResult(p.result)

		// Skip review when the LLM returned no changes.
		if strings.TrimSpace(p.result.Diff) == "" {
			session.Entries = append(session.Entries, sessionEntry{
				Title:    p.result.Candidate.Title,
				Severity: p.result.Candidate.Severity,
				File:     p.filePath,
				Action:   "skipped",
				Summary:  p.result.Summary,
			})
			continue
		}

		entry := sessionEntry{
			Title:    p.result.Candidate.Title,
			Severity: p.result.Candidate.Severity,
			File:     displayPath,
			Summary:  p.result.Summary,
			Diff:     p.result.Diff,
		}

		if autoAccept {
			applyFix(p.result, p.filePath)
			if p.result.FixedPath == "" {
				acceptedSrcByFile[p.filePath] = p.result.Fixed
			}
			entry.Action = "accepted"
			session.Entries = append(session.Entries, entry)
			continue
		}
		if autoReject {
			fmt.Printf("%s\n", styleReject.Render("  ✗ Skipped (reject all)"))
			entry.Action = "rejected"
			session.Entries = append(session.Entries, entry)
			continue
		}

		action := promptAction(stdin)
		fmt.Println()

		switch action {
		case "a", "A":
			applyFix(p.result, p.filePath)
			if p.result.FixedPath == "" {
				acceptedSrcByFile[p.filePath] = p.result.Fixed
			}
			entry.Action = "accepted"
			if action == "A" {
				autoAccept = true
			}

		case "r", "R":
			entry.Action = "rejected"
			if action == "R" {
				autoReject = true
				fmt.Printf("%s\n", styleReject.Render("  ✗ Skipped (reject all)"))
				session.Entries = append(session.Entries, entry)
				continue
			}
			fmt.Printf("%s\n", styleReject.Render("  ✗ Skipped"))

			// Re-generate subsequent fixes for the same file only.
			rejectedFile := p.filePath
			hasMore := false
			for j := i + 1; j < len(pending); j++ {
				if pending[j].filePath == rejectedFile {
					hasMore = true
					break
				}
			}
			if hasMore {
				fmt.Fprintf(os.Stderr, "\n%s\n", styleDim.Render("  Re-generating subsequent fixes..."))
				regenSrc := acceptedSrcByFile[rejectedFile]
				for j := i + 1; j < len(pending); j++ {
					if pending[j].filePath != rejectedFile {
						continue
					}
					candidate := pending[j].candidate
					src := regenSrc
					fp := rejectedFile
					r, err := generateWithSpinner(
						fmt.Sprintf("Re-generating: %s", candidate.Title),
						func() (*fixer.Result, error) {
							return fixer.FixContent(fp, src, candidate, client)
						},
					)
					if err != nil {
						fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
						continue
					}
					regenSrc = r.Fixed
					pending[j] = pendingFix{r, candidate, rejectedFile}
				}
			}

		case "q":
			session.Entries = append(session.Entries, entry)
			writeSessionLog(session, sourcePath)
			fmt.Println("Quitting.")
			return nil
		}
		session.Entries = append(session.Entries, entry)
	}

	writeSessionLog(session, sourcePath)
	return nil
}

// classFixParams bundles the fix-command flags relevant to a --class run.
type classFixParams struct {
	classPath       string
	outputDir       string
	runner          string
	baseImage       string
	sandboxArgs     string
	denyList        *policy.DenyList
	allowList       *policy.AllowList
	allowWriteTools bool
	envFixtures     map[string]string
	noCache         bool
	existingPolicy  string
	noSign          bool
	llmModel        string
	llmURL          string
	llmAPIKey       string
	llmTimeout      time.Duration
	outputFmt       string
	autoAcceptAll   bool
	concurrency     int
}

// classTarget is one (source, entrypoint) pair resolved from a class member:
// either the member's explicit entrypoint override, or one discovered inside
// the member's path via the same auto-discovery --source-with-no-entrypoint
// already uses.
type classTarget struct {
	source     string
	entrypoint string
}

// runClassFix probes every tool listed in a class YAML — each in its own
// sandbox run — and unions their observed egress into one policy, then hands
// off to the same post-scan pipeline (policy, attestation, fix generation,
// review, session log) a single-source run uses.
func runClassFix(p classFixParams) error {
	cls, err := class.Load(p.classPath)
	if err != nil {
		return fmt.Errorf("load class: %w", err)
	}

	var targets []classTarget
	for _, m := range cls.Tools {
		if m.Entrypoint != "" {
			targets = append(targets, classTarget{source: m.Path, entrypoint: m.Entrypoint})
			continue
		}
		tools, err := discover.FindTools(m.Path)
		if err != nil {
			return fmt.Errorf("discover tools in %s: %w", m.Path, err)
		}
		if len(tools) == 0 {
			return fmt.Errorf("no agent tool entrypoints found in %s (class %q) — set entrypoint explicitly in the class file", m.Path, cls.Name)
		}
		for _, t := range tools {
			targets = append(targets, classTarget{source: m.Path, entrypoint: t.Path})
		}
	}

	outputDir := p.outputDir
	if outputDir == "" {
		outputDir = filepath.Dir(p.classPath)
	}

	entrypointLabels := make([]string, len(targets))
	for i, t := range targets {
		entrypointLabels[i] = filepath.ToSlash(filepath.Join(t.source, t.entrypoint))
	}

	printBanner(outputDir, entrypointLabels, p.runner, p.baseImage, p.llmModel)
	fmt.Fprintf(os.Stderr, "%s  Probing class %s  %s\n",
		styleHeader.Render("◎"), styleHeader.Render(cls.Name),
		styleDim.Render(fmt.Sprintf("(%d tools)", len(targets))))

	// memberBaseImage looks up the per-member base_image override, if any.
	memberBaseImage := func(t classTarget) string {
		for _, m := range cls.Tools {
			if m.Path == t.source && (m.Entrypoint == "" || m.Entrypoint == t.entrypoint) {
				return m.BaseImage
			}
		}
		return ""
	}

	type targetResult struct {
		filePath   string
		candidates []sandbox.Candidate
		src        string
		harnessID  string
		cacheHit   bool
	}
	results := make([]targetResult, len(targets))
	srcContents := map[string]string{}
	var srcMu sync.Mutex

	// Resolved once for the whole class run: p.envFixtures is one shared map
	// (not per-member), and the cache directory is the same for every
	// target. cacheDir == "" means caching is unavailable or disabled
	// (--no-cache, or os.UserCacheDir() failed) — every lookup/save below is
	// a no-op in that case.
	fixturesHash := cache.HashFixtures(p.envFixtures)
	var cacheDir string
	if !p.noCache {
		cacheDir, _ = cache.Dir() // best-effort; empty on failure disables caching silently
	}

	sem := make(chan struct{}, max(1, p.concurrency))
	var wg sync.WaitGroup
	for i, t := range targets {
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int, t classTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			fp := filepath.Join(t.source, t.entrypoint)
			src, _ := os.ReadFile(fp)
			staticCandidates := analyzer.Analyze(fp, string(src))
			deps := analyzer.ExtractImports(fp, string(src))

			baseImg := memberBaseImage(t)
			if baseImg == "" {
				baseImg = p.baseImage
			}
			if baseImg == "" && p.runner != "docker" {
				baseImg = sandbox.DefaultBaseImage(t.entrypoint)
			}

			var runtime []sandbox.Candidate
			var r *sandbox.ScanResult
			var runErr error
			var harnessID string
			var cacheHit bool

			if !p.allowWriteTools {
				if evidence := analyzer.DetectsMutatingOperation(string(src)); len(evidence) > 0 {
					staticCandidates = append(staticCandidates, sandboxSkipFinding(evidence))
					fmt.Fprintf(os.Stderr, "  %s [%d/%d]  %s%s\n", stylePrompt.Render("⊘"), idx+1, len(targets), fp,
						styleDim.Render("  skipped — irreversible operation detected (use --allow-write-tools to override)"))
					srcMu.Lock()
					srcContents[fp] = string(src)
					srcMu.Unlock()
					results[idx] = targetResult{filePath: fp, candidates: mergeCandidates(nil, staticCandidates, string(src), fp), src: string(src)}
					return
				}
			}

			cacheKey := cache.Key(cache.KeyInput{
				Ext:          filepath.Ext(t.entrypoint),
				SourceHash:   cache.HashSource(src),
				Deps:         deps,
				Runner:       p.runner,
				BaseImage:    baseImg,
				SandboxArgs:  p.sandboxArgs,
				FixturesHash: fixturesHash,
				RulesVersion: cache.RulesVersion,
			})
			if cacheDir != "" {
				if cached, ok := cache.Load(cacheDir, cacheKey); ok {
					r, cacheHit = cached, true
				}
			}
			if r == nil {
				if p.runner == "docker" {
					r, runErr = sandbox.RunDocker(t.source, t.entrypoint, baseImg, p.sandboxArgs, "", deps, p.envFixtures)
				} else {
					r, runErr = sandbox.Run(t.source, t.entrypoint, baseImg, p.sandboxArgs, deps, p.envFixtures)
				}
				if runErr == nil && r != nil && cacheDir != "" {
					_ = cache.Save(cacheDir, cacheKey, r)
				}
			}

			icon := styleAccept.Render("✓")
			errSuffix := ""
			if runErr != nil {
				icon = styleReject.Render("✗")
				errSuffix = styleDim.Render("  " + runErr.Error())
			} else if r != nil {
				runtime = r.Candidates
				harnessID = r.SandboxID
			}
			if cacheHit {
				errSuffix += styleDim.Render("  (cached)")
			}
			fmt.Fprintf(os.Stderr, "  %s [%d/%d]  %s%s\n", icon, idx+1, len(targets), fp, errSuffix)
			if r != nil && r.Logs != "" {
				printSandboxOutput(r, styleHeader, styleDim)
			}

			merged := mergeCandidates(runtime, staticCandidates, string(src), fp)

			srcMu.Lock()
			srcContents[fp] = string(src)
			srcMu.Unlock()

			results[idx] = targetResult{filePath: fp, candidates: merged, src: string(src), harnessID: harnessID, cacheHit: cacheHit}
		}(i, t)
	}
	wg.Wait()

	var allCandidates []sandbox.Candidate
	var allFiles []fileCandidates
	for _, res := range results {
		allCandidates = append(allCandidates, res.candidates...)
		// Always record an allFiles entry, even with zero candidates — this
		// is the only place harnessID/cacheHit carry through to
		// runPostScan's toolInputs loop, so a genuinely clean tool must
		// still get an entry or its cache/harness provenance is silently
		// lost (candidates being empty is otherwise harmless downstream:
		// the fix-generation loop iterates f.candidates, which is just a
		// zero-length range for a clean file).
		allFiles = append(allFiles, fileCandidates{filePath: res.filePath, candidates: res.candidates, harnessID: res.harnessID, cacheHit: res.cacheHit})
	}

	return runPostScan(postScanParams{
		sourcePath:     outputDir,
		entrypoints:    entrypointLabels,
		class:          cls.Name,
		allCandidates:  allCandidates,
		allFiles:       allFiles,
		srcContents:    srcContents,
		denyList:       p.denyList,
		allowList:      p.allowList,
		existingPolicy: p.existingPolicy,
		noSign:         p.noSign,
		llmModel:       p.llmModel,
		llmURL:         p.llmURL,
		llmAPIKey:      p.llmAPIKey,
		llmTimeout:     p.llmTimeout,
		outputFmt:      p.outputFmt,
		autoAcceptAll:  p.autoAcceptAll,
		concurrency:    p.concurrency,
	})
}

func main() {
	var (
		sourcePath            string
		entrypoints           []string
		baseImage             string
		llmURL                string
		llmModel              string
		llmAPIKey             string
		llmTimeout            time.Duration
		outputFmt             string
		useSandbox            bool
		runner                string
		sandboxArgs           string
		existingPolicy        string
		denyListPath          string
		allowListPath         string
		platformAllowListPath string
		autoAcceptAll         bool
		noSign                bool
		concurrency           int
		classPath             string
		outputDir             string
		allowWriteTools       bool
		envFixturesPath       string
		noCache               bool
	)

	fixCmd := &cobra.Command{
		Use:   "fix",
		Short: "Observe an agent tool's network egress and generate a least-privilege OpenShell policy",
		Long: `Run an agent tool in an isolated sandbox, observe the network destinations it
actually reaches, and generate a least-privilege OpenShell network_policies YAML
from that evidence — plus AI-powered fixes for the issues found along the way,
reviewed one by one.

Static analysis runs by default (no external dependencies required).
Add --sandbox to also run the tool inside an isolated sandbox — OpenShell or
Docker, pick with --runner — and enrich findings with runtime evidence.
--runner docker needs only Docker installed and running; no OpenShell
install or gateway required.

When --sandbox is used, the base image is auto-detected from the entrypoint extension:
  .py        → python
  .go        → golang
  .js / .ts  → node
  .rb        → ruby

Override with --base-image if your sandbox needs a different image name.

After every scan, three files are always written to the source directory:
  network_policies.draft.yaml  — least-privilege OpenShell network_policies block (unsigned draft)
  probe.profile.json           — per-tool egress table and scan metadata (unsigned)
  autofix-attestation.json     — optional signed behavioral manifest (SHA256 content digest)`,
		Example: `  autofix fix --source ./my-tool --entrypoint tool.py
  autofix fix --source ./my-tool --entrypoint main.go --entrypoint utils.go
  autofix fix --source ./my-tool --entrypoint tool.py --sandbox
  autofix fix --source ./my-tool --entrypoint tool.py --existing-policy ./policy.yaml
  autofix fix --source ./my-tool --entrypoint tool.py --llm-url http://localhost:11434/v1 --model qwen2.5-coder:32b --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// --class and --source describe the same input (a list of tools to
			// probe) two different ways — inline shorthand vs. a class manifest —
			// not two separate "modes", but they can't both be given at once.
			if classPath != "" && sourcePath != "" {
				return fmt.Errorf("--class and --source cannot be used together")
			}
			if classPath == "" && sourcePath == "" {
				return fmt.Errorf("either --source or --class is required")
			}
			if classPath != "" && len(entrypoints) > 0 {
				return fmt.Errorf("--entrypoint cannot be used with --class — list entrypoints in the class file instead")
			}
			if classPath != "" && !useSandbox {
				return fmt.Errorf("--class requires --sandbox — class-level probing needs real runtime egress, not just static analysis")
			}

			// Repo mode: auto-discover when no --entrypoint provided (single-source only).
			repoMode := classPath == "" && len(entrypoints) == 0
			if repoMode {
				tools, err := discover.FindTools(sourcePath)
				if err != nil {
					return fmt.Errorf("discovery failed: %w", err)
				}
				if len(tools) == 0 {
					return fmt.Errorf("no agent tool entrypoints found in %s — use --entrypoint to specify one explicitly", sourcePath)
				}
				for _, t := range tools {
					entrypoints = append(entrypoints, t.Path)
				}
			}

			denyList := policy.BuiltinDenyList()
			if denyListPath != "" {
				custom, err := policy.LoadDenyList(denyListPath)
				if err != nil {
					return fmt.Errorf("load deny list: %w", err)
				}
				denyList = policy.Merge(denyList, custom)
			}

			var allowList *policy.AllowList
			if allowListPath != "" || platformAllowListPath != "" {
				allowList = policy.NewAllowList()
				if allowListPath != "" {
					declared, err := policy.LoadAllowList(allowListPath, policy.SourceDeclared)
					if err != nil {
						return fmt.Errorf("load allow list: %w", err)
					}
					allowList = policy.MergeAllow(allowList, declared)
				}
				if platformAllowListPath != "" {
					platform, err := policy.LoadAllowList(platformAllowListPath, policy.SourcePlatform)
					if err != nil {
						return fmt.Errorf("load platform allow list: %w", err)
					}
					allowList = policy.MergeAllow(allowList, platform)
				}
				if broad := allowList.BroadEntries(); len(broad) > 0 {
					fmt.Fprintf(os.Stderr, "%s  Broad allow-list entries detected: %s\n", stylePrompt.Render("⚠"), strings.Join(broad, ", "))
				}
			}

			var envFixtures map[string]string
			if envFixturesPath != "" {
				var err error
				envFixtures, err = sandbox.LoadEnvFixtures(envFixturesPath)
				if err != nil {
					return fmt.Errorf("load env fixtures: %w", err)
				}
			}

			// BYOK: resolve API key from env when not explicitly provided.
			if llmAPIKey == "" || llmAPIKey == "dummy" {
				for _, env := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "LLM_API_KEY"} {
					if v := os.Getenv(env); v != "" {
						llmAPIKey = v
						break
					}
				}
			}
			if llmModel == "" {
				return fmt.Errorf("--model is required (e.g. --model gpt-4o, --model qwen2.5-coder:32b)")
			}
			// Auto-detect endpoint URL from model name; require --llm-url for unknown models.
			if llmURL == "" {
				switch {
				case strings.HasPrefix(llmModel, "gpt-") || strings.HasPrefix(llmModel, "o1") || strings.HasPrefix(llmModel, "o3"):
					llmURL = "https://api.openai.com/v1"
				case strings.HasPrefix(llmModel, "claude-"):
					llmURL = "https://api.anthropic.com/v1"
				default:
					return fmt.Errorf("--llm-url is required for model %q (cannot auto-detect endpoint)", llmModel)
				}
			}

			if classPath != "" {
				return runClassFix(classFixParams{
					classPath:       classPath,
					outputDir:       outputDir,
					runner:          runner,
					baseImage:       baseImage,
					sandboxArgs:     sandboxArgs,
					denyList:        denyList,
					allowList:       allowList,
					allowWriteTools: allowWriteTools,
					envFixtures:     envFixtures,
					noCache:         noCache,
					existingPolicy:  existingPolicy,
					noSign:          noSign,
					llmModel:        llmModel,
					llmURL:          llmURL,
					llmAPIKey:       llmAPIKey,
					llmTimeout:      llmTimeout,
					outputFmt:       outputFmt,
					autoAcceptAll:   autoAcceptAll,
					concurrency:     concurrency,
				})
			}

			// Resolve the sandbox base image before printing the banner so the
			// banner always shows what will actually be used.
			sbImg := baseImage
			if sbImg == "" {
				switch {
				case runner == "docker":
					// RunDocker resolves a per-entrypoint image internally
					// (dockerBaseImage) — sandbox.MultiLangImage
					// (trustabl/sandbox:latest) is unpublished; never default to it.
				default:
					// OpenShell always defaults to openclaw — trustabl/sandbox is not yet
					// published and using it causes sandbox create to hang/timeout.
					sbImg = sandbox.DefaultBaseImage(entrypoints[0])
				}
			}
			displayImg := sbImg
			if displayImg == "" {
				displayImg = "auto"
			}

			printBanner(sourcePath, entrypoints, runner, sbImg, llmModel)

			// Collect candidates per file.
			// In single-tool mode, the sandbox runs once upfront for the main entrypoint.
			// In repo mode, the sandbox runs per-entrypoint so each tool's runtime behaviour
			// is captured independently.
			var allFiles []fileCandidates
			var allCandidates []sandbox.Candidate
			srcContents := map[string]string{}

			// Collect Python deps across all entrypoints.
			// Docker: deps are installed inside a network-enabled setup container (two-phase).
			// OpenShell: dep list passed to Run() for wheel download + upload into sandbox.
			var sharedDepsDir string
			var allDeps []string
			if useSandbox {
				seenDeps := map[string]bool{}
				for _, ep := range entrypoints {
					fp := filepath.Join(sourcePath, ep)
					src, _ := os.ReadFile(fp)
					for _, d := range analyzer.ExtractImports(fp, string(src)) {
						if !seenDeps[d] {
							seenDeps[d] = true
							allDeps = append(allDeps, d)
						}
					}
				}
			}
			_ = sharedDepsDir // unused for docker; kept for OpenShell path

			// Resolved once for the whole run: envFixtures is one shared map
			// (not per-entrypoint), and the cache directory is the same for
			// every entrypoint. cacheDir == "" means caching is unavailable
			// or disabled (--no-cache, or os.UserCacheDir() failed) — every
			// lookup/save below is a no-op in that case.
			fixturesHash := cache.HashFixtures(envFixtures)
			var cacheDir string
			if useSandbox && !noCache {
				cacheDir, _ = cache.Dir() // best-effort; empty on failure disables caching silently
			}
			cacheKeyFor := func(ep string, src []byte, baseImage string) string {
				return cache.Key(cache.KeyInput{
					Ext:          filepath.Ext(ep),
					SourceHash:   cache.HashSource(src),
					Deps:         allDeps,
					Runner:       runner,
					BaseImage:    baseImage,
					SandboxArgs:  sandboxArgs,
					FixturesHash: fixturesHash,
					RulesVersion: cache.RulesVersion,
				})
			}

			// Collect static analysis results for all files immediately (fast).
			type staticResult struct {
				fp  string
				src string
				cs  []sandbox.Candidate
			}
			var statics []staticResult
			// skipSandbox marks entrypoints whose sandbox execution is skipped by
			// default because their code contains a mutating/irreversible call
			// shape — harness safety rules, so a default Probe run cannot cause a
			// real-world side effect. Only computed when sandbox execution would
			// otherwise happen; --allow-write-tools disables the gate entirely.
			skipSandbox := map[string]bool{}
			for _, ep := range entrypoints {
				fp := filepath.Join(sourcePath, ep)
				if ext := filepath.Ext(ep); !map[string]bool{
					".py": true, ".go": true,
					".js": true, ".ts": true, ".jsx": true, ".tsx": true, ".mjs": true, ".cjs": true,
					".rb": true, ".sh": true, ".bash": true,
				}[ext] {
					fmt.Fprintf(os.Stderr, "%s  No static analysis rules for %s — supported: Python, Go, JS/TS, Ruby, Shell (sandbox runtime findings still apply)\n",
						stylePrompt.Render("⚠"), ep)
				}
				src, _ := os.ReadFile(fp)
				cs := analyzer.Analyze(fp, string(src))
				if useSandbox && !allowWriteTools {
					if evidence := analyzer.DetectsMutatingOperation(string(src)); len(evidence) > 0 {
						skipSandbox[ep] = true
						cs = append(cs, sandboxSkipFinding(evidence))
					}
				}
				statics = append(statics, staticResult{fp, string(src), cs})
				srcContents[fp] = string(src)
			}

			// Open one shared sandbox for the entire run (repo mode reuses it across
			// tools; single-tool mode runs it concurrently with static analysis above).
			type sbOutcome struct {
				results   map[string]*sandbox.ScanResult // keyed by entrypoint
				cacheHits map[string]bool                // keyed by entrypoint
				handle    *sandbox.SandboxHandle         // non-nil for openshell; caller must Close
				err       error
			}
			sbCh := make(chan sbOutcome, 1)

			// Shell scripts are skipped for sandbox execution regardless of runner —
			// static analysis is sufficient and executing arbitrary shell in a sandbox
			// adds risk without meaningful extra signal.
			for _, ep := range entrypoints {
				if ext := filepath.Ext(ep); ext == ".sh" || ext == ".bash" {
					if sandboxArgs != "" {
						fmt.Fprintf(os.Stderr,
							"%s  --sandbox-args has no effect for shell scripts — sandbox execution is not supported for shell.\n",
							stylePrompt.Render("⚠"))
					}
					if useSandbox {
						fmt.Fprintf(os.Stderr,
							"%s  Sandbox skipped for %s — shell scripts are analyzed statically only.\n",
							stylePrompt.Render("⚠"), ep)
						useSandbox = false
					}
					break
				}
			}

			if useSandbox && runner != "docker" {
				// openclaw only ships Python and Node.js — skip sandbox for other languages
				// and tell the user how to get full runtime coverage.
				unsupported := map[string]bool{
					".go": true, ".rb": true,
				}
				for _, ep := range entrypoints {
					if unsupported[filepath.Ext(ep)] {
						fmt.Fprintf(os.Stderr,
							"%s  Sandbox skipped for %s — openclaw does not include a %s runtime.\n    Use --runner docker for full sandbox coverage of this language.\n",
							stylePrompt.Render("⚠"), ep, strings.TrimPrefix(filepath.Ext(ep), "."))
						useSandbox = false
						break
					}
				}
			}

			if useSandbox {
				fmt.Fprintf(os.Stderr, "%s  Starting sandbox  %s\n",
					styleHeader.Render("◎"),
					styleDim.Render("(runner: "+runner+", base: "+displayImg+")"),
				)
				go func() {
					results := map[string]*sandbox.ScanResult{}
					cacheHits := map[string]bool{}
					var h *sandbox.SandboxHandle
					if runner == "docker" {
						sbCap := concurrency
						if sbCap > len(entrypoints) {
							sbCap = len(entrypoints)
						}

						renderSbProgress := func(n, total int) {
							pct := 0
							if total > 0 {
								pct = n * 100 / total
							}
							const barWidth = 20
							filled := 0
							if total > 0 {
								filled = n * barWidth / total
							}
							bar := styleAccept.Render(strings.Repeat("█", filled)) +
								styleDim.Render(strings.Repeat("░", barWidth-filled))
							suffix := ""
							if n == total && total > 0 {
								suffix = "  " + styleAccept.Render("done")
							}
							fmt.Fprintf(os.Stderr, "\r  [%s]  %3d%%  %d/%d%s",
								bar, pct, n, total, suffix)
						}

						var (
							sbProgressMu sync.Mutex
							sbCompleted  int
						)
						renderSbProgress(0, len(entrypoints))

						sbSem := make(chan struct{}, sbCap)
						var sbWg sync.WaitGroup
						for _, ep := range entrypoints {
							sbSem <- struct{}{}
							sbWg.Add(1)
							go func(ep string) {
								defer sbWg.Done()
								defer func() { <-sbSem }()

								if skipSandbox[ep] {
									sbProgressMu.Lock()
									results[ep] = &sandbox.ScanResult{}
									sbCompleted++
									n := sbCompleted
									fmt.Fprintf(os.Stderr, "\r\033[K")
									fmt.Fprintf(os.Stderr, "  %s [%d/%d]  %-38s %s\n",
										stylePrompt.Render("⊘"), n, len(entrypoints), ep,
										styleDim.Render("skipped — irreversible operation detected (use --allow-write-tools to override)"),
									)
									renderSbProgress(n, len(entrypoints))
									sbProgressMu.Unlock()
									return
								}

								fp := filepath.Join(sourcePath, ep)
								epSrc, _ := os.ReadFile(fp)
								cacheKey := cacheKeyFor(ep, epSrc, sbImg)
								var r *sandbox.ScanResult
								var err error
								var hit bool
								if cacheDir != "" {
									if cached, ok := cache.Load(cacheDir, cacheKey); ok {
										r, hit = cached, true
									}
								}

								start := time.Now()
								if r == nil {
									r, err = sandbox.RunDocker(sourcePath, ep, sbImg, sandboxArgs, sharedDepsDir, allDeps, envFixtures)
									if err == nil && r != nil && cacheDir != "" {
										_ = cache.Save(cacheDir, cacheKey, r)
									}
								}
								elapsed := time.Since(start)

								icon := styleAccept.Render("✓")
								errSuffix := ""
								candidates := 0
								if err != nil {
									icon = styleReject.Render("✗")
									errSuffix = styleDim.Render("  " + err.Error())
								} else if r != nil {
									candidates = len(r.Candidates)
								}
								if hit {
									errSuffix += styleDim.Render("  (cached)")
								}
								candidateWord := "candidates"
								if candidates == 1 {
									candidateWord = "candidate"
								}

								sbProgressMu.Lock()
								if err != nil {
									results[ep] = &sandbox.ScanResult{}
								} else {
									results[ep] = r
									cacheHits[ep] = hit
								}
								sbCompleted++
								n := sbCompleted
								fmt.Fprintf(os.Stderr, "\r\033[K")
								fmt.Fprintf(os.Stderr, "  %s [%d/%d]  %-38s %d %s  %s%s\n",
									icon, n, len(entrypoints), ep,
									candidates, candidateWord,
									styleDim.Render(fmt.Sprintf("%.1fs", elapsed.Seconds())),
									errSuffix,
								)
								renderSbProgress(n, len(entrypoints))
								sbProgressMu.Unlock()
							}(ep)
						}
						sbWg.Wait()
						fmt.Fprintln(os.Stderr)
					} else {
						var err error
						h, err = sandbox.OpenSandbox(sbImg)
						if err != nil {
							sbCh <- sbOutcome{err: err}
							return
						}
						if len(allDeps) > 0 {
							spinErr(
								fmt.Sprintf("Installing deps: %s", strings.Join(allDeps, " ")),
								func() error { h.UploadDeps(allDeps); return nil },
							)
						}
						// Only escalate to project root when an entrypoint imports a local
						// package that lives outside sourcePath (e.g. from examples.utils
						// import ... when examples/ is at the repo root). For tools with
						// only pip deps, upload just sourcePath to keep the sandbox small.
						absSource, _ := filepath.Abs(sourcePath)
						uploadRoot := absSource // default: upload just the tool directory
						for _, ep := range entrypoints {
							fp := filepath.Join(sourcePath, ep)
							src, _ := os.ReadFile(fp)
							for _, localPkg := range analyzer.FindLocalPackages(fp, string(src)) {
								absLocal, _ := filepath.Abs(localPkg)
								if !strings.HasPrefix(absLocal, absSource) {
									uploadRoot = sandbox.FindProjectRoot(sourcePath)
									break
								}
							}
							if uploadRoot != absSource {
								break
							}
						}
						if err := spinErr("Uploading project files", func() error {
							return h.Upload(uploadRoot)
						}); err != nil {
							fmt.Fprintf(os.Stderr, "Warning: sandbox upload failed: %v\n", err)
						}
						// Compute entrypoints relative to the upload root so paths inside
						// the sandbox match the uploaded directory structure.
						absProject, _ := filepath.Abs(uploadRoot)
						for i, ep := range entrypoints {
							absEp, _ := filepath.Abs(filepath.Join(sourcePath, ep))
							relEp, err := filepath.Rel(absProject, absEp)
							if err != nil || relEp == "" {
								relEp = ep
							}
							// The sandbox exec command is a POSIX shell string — a
							// backslash-separated Windows path would have its
							// separators stripped by shell escaping, mangling the
							// path (e.g. "a\b\c.py" -> "abc.py").
							relEp = filepath.ToSlash(relEp)
							label := relEp
							if len(entrypoints) > 1 {
								label = fmt.Sprintf("%s %s", relEp, styleDim.Render(fmt.Sprintf("[%d/%d reusing sandbox]", i+1, len(entrypoints))))
							}
							if skipSandbox[ep] {
								fmt.Fprintf(os.Stderr, "%s  Skipping %s  %s\n", stylePrompt.Render("⊘"), styleHeader.Render(label),
									styleDim.Render("(irreversible operation detected — use --allow-write-tools to override)"))
								results[ep] = &sandbox.ScanResult{}
								continue
							}
							epSrc, _ := os.ReadFile(filepath.Join(sourcePath, ep))
							cacheKey := cacheKeyFor(ep, epSrc, sbImg)
							if cacheDir != "" {
								if cached, ok := cache.Load(cacheDir, cacheKey); ok {
									results[ep] = cached
									cacheHits[ep] = true
									fmt.Fprintf(os.Stderr, "%s  %s  %s\n", styleAccept.Render("✓"), styleHeader.Render(label), styleDim.Render("(cached)"))
									continue
								}
							}
							fmt.Fprintf(os.Stderr, "%s  Running %s\n", styleHeader.Render("◎"), styleHeader.Render(label))
							r, err := h.Exec(uploadRoot, relEp, sandboxArgs, envFixtures)
							if err != nil {
								fmt.Fprintf(os.Stderr, "Warning: exec failed for %s: %v\n", ep, err)
								results[ep] = &sandbox.ScanResult{}
							} else {
								results[ep] = r
								if cacheDir != "" {
									_ = cache.Save(cacheDir, cacheKey, r)
								}
							}
						}
					}
					sbCh <- sbOutcome{results: results, cacheHits: cacheHits, handle: h}
				}()
			} else {
				sbCh <- sbOutcome{results: map[string]*sandbox.ScanResult{}}
			}

			// Wait for sandbox (static analysis already done above).
			sbOut := <-sbCh
			if sbOut.err != nil {
				fmt.Fprintf(os.Stderr, "Warning: sandbox unavailable (%v) — using static analysis only\n\n", sbOut.err)
				sbOut.results = map[string]*sandbox.ScanResult{}
			}
			if useSandbox {
				for _, ep := range entrypoints {
					if r, ok := sbOut.results[ep]; ok && r.Logs != "" {
						printSandboxOutput(r, styleHeader, styleDim)
					}
				}
				if sbOut.handle != nil {
					_ = spinErr("Deleting sandbox", func() error {
						sbOut.handle.Close()
						return nil
					})
				}
			}

			for _, s := range statics {
				var runtime []sandbox.Candidate
				var harnessID string
				var cacheHit bool
				if r, ok := sbOut.results[filepath.Base(s.fp)]; ok {
					runtime = r.Candidates
					harnessID = r.SandboxID
					cacheHit = sbOut.cacheHits[filepath.Base(s.fp)]
				}
				// Also check by full ep name.
				for _, ep := range entrypoints {
					if sourcePath+"/"+ep == s.fp {
						if r, ok := sbOut.results[ep]; ok {
							runtime = r.Candidates
							harnessID = r.SandboxID
							cacheHit = sbOut.cacheHits[ep]
						}
					}
				}
				merged := mergeCandidates(runtime, s.cs, s.src, s.fp)
				allCandidates = append(allCandidates, merged...)
				// Always record an allFiles entry — see the matching comment
				// in runClassFix for why a zero-candidate tool still needs
				// one (harnessID/cacheHit provenance would otherwise be
				// silently lost for the exact tools most likely to be
				// clean, cache-friendly reruns).
				allFiles = append(allFiles, fileCandidates{filePath: s.fp, candidates: merged, harnessID: harnessID, cacheHit: cacheHit})
			}

			return runPostScan(postScanParams{
				sourcePath:     sourcePath,
				entrypoints:    entrypoints,
				allCandidates:  allCandidates,
				allFiles:       allFiles,
				srcContents:    srcContents,
				denyList:       denyList,
				allowList:      allowList,
				existingPolicy: existingPolicy,
				noSign:         noSign,
				llmModel:       llmModel,
				llmURL:         llmURL,
				llmAPIKey:      llmAPIKey,
				llmTimeout:     llmTimeout,
				outputFmt:      outputFmt,
				autoAcceptAll:  autoAcceptAll,
				concurrency:    concurrency,
			})
		},
	}

	fixCmd.Flags().StringVar(&sourcePath, "source", "", "Path to the tool directory — required unless --class is given")
	fixCmd.Flags().StringArrayVar(&entrypoints, "entrypoint", nil,
		"Entry point script(s) within the tool directory (can be repeated for multi-file scanning; not usable with --class)")
	fixCmd.Flags().StringVar(&classPath, "class", "", "Path to a class YAML listing the tools that make up an agent class — required unless --source is given")
	fixCmd.Flags().StringVar(&outputDir, "output-dir", "", "Directory to write policy/attestation/session files into for a --class run (default: the class file's own directory)")
	fixCmd.Flags().StringVar(&baseImage, "base-image", "", "Sandbox base image for --runner openshell or docker (default: auto-detected from entrypoint extension)")
	fixCmd.Flags().StringVar(&llmURL, "llm-url", "", "OpenAI-compatible LLM base URL (auto-detected from model name for gpt-* and claude-* models; required for other models)")
	fixCmd.Flags().StringVar(&llmModel, "model", "", "Model name to use (e.g. gpt-4o, claude-3-5-sonnet-20241022, qwen2.5-coder:32b)")
	fixCmd.Flags().StringVar(&llmAPIKey, "api-key", "", "API key (defaults to OPENAI_API_KEY / ANTHROPIC_API_KEY / LLM_API_KEY env vars)")
	fixCmd.Flags().DurationVar(&llmTimeout, "llm-timeout", llm.DefaultTimeout, "Per-request LLM timeout (increase for slow local models, e.g. --llm-timeout 10m)")
	fixCmd.Flags().StringVar(&outputFmt, "output", "text", "Output format: text or json")
	fixCmd.Flags().BoolVar(&useSandbox, "sandbox", false, "Run the tool in a sandbox for runtime policy log findings")
	fixCmd.Flags().StringVar(&runner, "runner", "openshell", "Sandbox runner to use: openshell or docker")
	fixCmd.Flags().StringVar(&sandboxArgs, "sandbox-args", "", "Arguments to pass to the tool when running inside the sandbox (e.g. --sandbox-args \"London\"). Value is passed as a raw shell token — avoid shell metacharacters.")
	fixCmd.Flags().StringVar(&existingPolicy, "existing-policy", "",
		"Path to an existing OpenShell policy YAML to diff against the generated least-privilege policy")
	fixCmd.Flags().StringVar(&denyListPath, "deny-list", "",
		"Path to a deny list file (one host/IP/CIDR per line, # comments) — evaluated on top of the built-in metadata/link-local deny")
	fixCmd.Flags().StringVar(&allowListPath, "allow-list", "",
		"Path to a declared allow list file (one host/CIDR/*.suffix per line, # comments) — an observed destination not on this list is flagged, not auto-added to the draft")
	fixCmd.Flags().StringVar(&platformAllowListPath, "platform-allow-list", "",
		"Path to a platform allow list file (jail must-reach endpoints, e.g. NIM/IdP) — same format as --allow-list, tagged source=platform in probe.profile.json")
	fixCmd.Flags().BoolVar(&allowWriteTools, "allow-write-tools", false,
		"Allow sandbox execution of tools that appear to perform mutating/irreversible operations (default: skipped, static analysis only)")
	fixCmd.Flags().StringVar(&envFixturesPath, "env-fixtures", "",
		"Path to a dotenv-style file (KEY=value per line, # comments) injected into the sandbox environment — lets a tool pick up staging credentials/endpoints instead of production ones")
	fixCmd.Flags().BoolVar(&noCache, "no-cache", false,
		"Skip the per-tool result cache entirely — neither read nor write it (use for release gates that must always execute for real)")
	fixCmd.Flags().BoolVar(&autoAcceptAll, "auto-accept", false, "Accept all generated fixes without interactive review (useful for CI or batch runs)")
	fixCmd.Flags().BoolVar(&noSign, "no-sign", false, "Skip Sigstore signing entirely — no network call, no interactive OIDC browser flow, no public transparency log entry")
	fixCmd.Flags().IntVar(&concurrency, "concurrency", 3, "Max files processed in parallel during fix generation (1 = sequential, same as previous behaviour)")

	// ── watch command ────────────────────────────────────────────────────────────
	var (
		watchSource        string
		watchEntrypoints   []string
		watchInterval      time.Duration
		watchNoSign        bool
		watchDenyList      string
		watchAllowList     string
		watchPlatformAllow string
	)

	watchCmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch source files and regenerate the least-privilege policy on change",
		Long: `Poll source files for changes. When any file is modified, re-runs static
analysis, regenerates network_policies.draft.yaml, probe.profile.json, and
autofix-attestation.json, and prints a delta showing score changes and
added/resolved findings.

This demonstrates the continuous improvement loop:
  Edit tool → Trustabl detects drift → Policy + profile + attestation auto-updated.`,
		Example: `  autofix watch --source ./my-tool
  autofix watch --source ./my-tool --entrypoint tool.py --interval 1s`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Auto-discover entrypoints when not provided.
			eps := watchEntrypoints
			if len(eps) == 0 {
				tools, err := discover.FindTools(watchSource)
				if err != nil {
					return fmt.Errorf("discovery failed: %w", err)
				}
				for _, t := range tools {
					eps = append(eps, t.Path)
				}
				if len(eps) == 0 {
					return fmt.Errorf("no agent tool entrypoints found in %s", watchSource)
				}
			}

			denyList := policy.BuiltinDenyList()
			if watchDenyList != "" {
				custom, err := policy.LoadDenyList(watchDenyList)
				if err != nil {
					return fmt.Errorf("load deny list: %w", err)
				}
				denyList = policy.Merge(denyList, custom)
			}

			var allowList *policy.AllowList
			if watchAllowList != "" || watchPlatformAllow != "" {
				allowList = policy.NewAllowList()
				if watchAllowList != "" {
					declared, err := policy.LoadAllowList(watchAllowList, policy.SourceDeclared)
					if err != nil {
						return fmt.Errorf("load allow list: %w", err)
					}
					allowList = policy.MergeAllow(allowList, declared)
				}
				if watchPlatformAllow != "" {
					platform, err := policy.LoadAllowList(watchPlatformAllow, policy.SourcePlatform)
					if err != nil {
						return fmt.Errorf("load platform allow list: %w", err)
					}
					allowList = policy.MergeAllow(allowList, platform)
				}
				if broad := allowList.BroadEntries(); len(broad) > 0 {
					fmt.Fprintf(os.Stderr, "%s  Broad allow-list entries detected: %s\n", stylePrompt.Render("⚠"), strings.Join(broad, ", "))
				}
			}

			// watchScan runs static analysis and regenerates policy + attestation.
			// Returns (manifest, candidates) for delta comparison.
			type scanSnapshot struct {
				manifest   *attestation.Manifest
				candidates []sandbox.Candidate
			}
			watchScan := func() (*scanSnapshot, error) {
				srcContents := map[string]string{}
				var allCandidates []sandbox.Candidate
				var toolInputs []profile.ToolInput
				for _, ep := range eps {
					fp := filepath.Join(watchSource, ep)
					src, err := os.ReadFile(fp)
					if err != nil {
						return nil, fmt.Errorf("read %s: %w", fp, err)
					}
					srcContents[fp] = string(src)
					candidates := analyzer.Analyze(fp, string(src))
					merged := mergeCandidates(nil, candidates, string(src), fp)
					_, denied, notInAllow := policy.ExtractToolEndpoints(merged, string(src), denyList, allowList)
					if len(denied) > 0 {
						merged = append(merged, denyFinding(denied))
					}
					if len(notInAllow) > 0 {
						merged = append(merged, notInOrgAllowFinding(notInAllow))
					}
					allCandidates = append(allCandidates, merged...)
					toolInputs = append(toolInputs, profile.ToolInput{
						Path:       filepath.ToSlash(fp),
						Language:   attestation.ExtToLanguage(filepath.Ext(fp)),
						Candidates: merged,
						Src:        string(src),
						// No HarnessID: watch is static-analysis-only, no sandbox run.
					})
				}
				policyDoc := policy.Generate(allCandidates, srcContents, denyList, allowList)
				_ = policy.WritePolicy(policyDoc, watchSource)
				m := attestation.Build(allCandidates, eps, watchSource, policyDoc)
				_ = attestation.Write(m, watchSource, watchNoSign)
				toolProfile := profile.Build(watchSource, "", toolInputs, denyList, allowList)
				_ = profile.Write(toolProfile, watchSource)
				_ = findings.Write(findings.Build(watchSource, "", toolInputs, nil), watchSource)
				return &scanSnapshot{manifest: m, candidates: allCandidates}, nil
			}

			// sourceFilesMtime returns a map of filepath → mtime for all source files.
			sourceFilesMtime := func() map[string]time.Time {
				mtimes := map[string]time.Time{}
				for _, ep := range eps {
					fp := filepath.Join(watchSource, ep)
					if info, err := os.Stat(fp); err == nil {
						mtimes[fp] = info.ModTime()
					}
				}
				return mtimes
			}

			// Initial scan.
			snap, err := watchScan()
			if err != nil {
				return err
			}
			printAttestationCard(snap.manifest, styleHeader, styleAccept, stylePrompt, styleReject, styleDim)
			fmt.Fprintf(os.Stderr, "%s\n\n", styleDim.Render("Attestation written to "+watchSource+"/autofix-attestation.json"))
			fmt.Fprintf(os.Stderr, "%s  %s  %s\n\n",
				styleHeader.Render("◎ Watching"),
				styleHeader.Render(watchSource),
				styleDim.Render("(interval: "+watchInterval.String()+")  Ctrl+C to stop"),
			)

			prevMtimes := sourceFilesMtime()
			prevSnap := snap

			// Signal handler for clean Ctrl+C exit.
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt)
			ticker := time.NewTicker(watchInterval)
			defer ticker.Stop()

			for {
				select {
				case <-sigCh:
					fmt.Fprintln(os.Stderr, "\nStopped.")
					return nil
				case <-ticker.C:
					cur := sourceFilesMtime()
					changed := false
					for fp, mtime := range cur {
						if prev, ok := prevMtimes[fp]; !ok || mtime.After(prev) {
							changed = true
							break
						}
					}
					if !changed {
						continue
					}
					prevMtimes = cur

					fmt.Fprintf(os.Stderr, "\n  %s  Source changed — re-scanning...\n", stylePrompt.Render("↻"))
					newSnap, err := watchScan()
					if err != nil {
						fmt.Fprintf(os.Stderr, "  %s scan error: %v\n", styleReject.Render("✗"), err)
						continue
					}

					// Print delta.
					oldScore := prevSnap.manifest.ProductionReadinessScore
					newScore := newSnap.manifest.ProductionReadinessScore
					diff := newScore - oldScore
					sign := "+"
					scoreStyle := styleAccept
					if diff < 0 {
						sign = ""
						scoreStyle = styleReject
					}
					fmt.Fprintf(os.Stderr, "  %s  Score: %s → %s  %s\n",
						scoreStyle.Render("✓"),
						styleDim.Render(fmt.Sprintf("%d", oldScore)),
						scoreStyle.Render(fmt.Sprintf("%d", newScore)),
						scoreStyle.Render(fmt.Sprintf("(%s%d)", sign, diff)),
					)

					oldCount := len(prevSnap.candidates)
					newCount := len(newSnap.candidates)
					resolved := oldCount - newCount
					if resolved > 0 {
						fmt.Fprintf(os.Stderr, "  %s  %d finding(s) resolved  (%d remaining)\n",
							styleAccept.Render("✓"), resolved, newCount)
					} else if newCount > oldCount {
						fmt.Fprintf(os.Stderr, "  %s  %d new finding(s)  (%d total)\n",
							styleReject.Render("✗"), newCount-oldCount, newCount)
					}

					oldHash := prevSnap.manifest.SourceHash
					newHash := newSnap.manifest.SourceHash
					if oldHash != newHash {
						short := newHash
						if len(short) > 16 {
							short = short[:16] + "..."
						}
						fmt.Fprintf(os.Stderr, "  %s\n",
							styleDim.Render("source:"+short+"  ← new fingerprint"),
						)
					}
					fmt.Fprintf(os.Stderr, "  %s\n",
						styleDim.Render("Attestation updated → "+watchSource+"/autofix-attestation.json"),
					)
					prevSnap = newSnap
				}
			}
		},
	}

	watchCmd.Flags().StringVar(&watchSource, "source", "", "Path to the tool directory to watch (required)")
	watchCmd.Flags().StringArrayVar(&watchEntrypoints, "entrypoint", nil, "Entry point script(s) to watch (auto-discovered if omitted)")
	watchCmd.Flags().DurationVar(&watchInterval, "interval", 2*time.Second, "Poll interval for file change detection")
	watchCmd.Flags().BoolVar(&watchNoSign, "no-sign", false, "Skip Sigstore signing entirely — no network call, no interactive OIDC browser flow, no public transparency log entry")
	watchCmd.Flags().StringVar(&watchDenyList, "deny-list", "",
		"Path to a deny list file (one host/IP/CIDR per line, # comments) — evaluated on top of the built-in metadata/link-local deny")
	watchCmd.Flags().StringVar(&watchAllowList, "allow-list", "",
		"Path to a declared allow list file (one host/CIDR/*.suffix per line, # comments) — an observed destination not on this list is flagged, not auto-added to the draft")
	watchCmd.Flags().StringVar(&watchPlatformAllow, "platform-allow-list", "",
		"Path to a platform allow list file (jail must-reach endpoints, e.g. NIM/IdP) — same format as --allow-list, tagged source=platform in probe.profile.json")
	watchCmd.MarkFlagRequired("source")

	// ─────────────────────────────────────────────────────────────────────────────

	root := &cobra.Command{
		Use:   "autofix",
		Short: "Network egress evidence and least-privilege OpenShell policy for agent tools",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			showLicenseBannerOnce(cmd.Name())
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the build version",
		Run:   func(cmd *cobra.Command, args []string) { fmt.Println(version) },
	}

	root.AddCommand(fixCmd, watchCmd, verifyCmd, versionCmd, licenseCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
