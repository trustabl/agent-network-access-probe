package discover

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Tool represents a discovered agent tool entrypoint.
type Tool struct {
	Path     string // relative path from repo root
	Language string // "python" | "go" | "node" | "ruby" | "shell"
}

// agentSDKs are Python package prefixes that indicate a file is an agent tool.
// Files detected only by __main__ guard must import at least one of these.
var agentSDKs = []string{
	"mcp", "anthropic", "openai", "langchain", "llama_index",
	"crewai", "autogen", "semantic_kernel", "haystack", "embedchain",
	"pydantic_ai", "google.generativeai", "agents",
}

func hasAgentImport(body string) bool {
	for _, sdk := range agentSDKs {
		if strings.Contains(body, "import "+sdk) ||
			strings.Contains(body, "from "+sdk) {
			return true
		}
	}
	return false
}

// skipDirs are directory names that are always pruned during the walk.
var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, "dist": true,
	"build": true, "__pycache__": true, ".venv": true, "venv": true,
	".idea": true, ".claude": true, "testdata": true,
}

// isTestFile returns true for files that are clearly test/spec artifacts.
func isTestFile(name string) bool {
	return strings.HasSuffix(name, "_test.go") ||
		strings.HasPrefix(name, "test_") ||
		strings.HasSuffix(name, "_test.py") ||
		strings.HasSuffix(name, ".test.js") ||
		strings.HasSuffix(name, ".test.ts") ||
		strings.HasSuffix(name, ".spec.js") ||
		strings.HasSuffix(name, ".spec.ts")
}

// entrypointNames are filenames that are unconditionally treated as entrypoints.
var entrypointNames = map[string]string{
	"main.py":   "python",
	"server.py": "python",
	"tool.py":   "python",
	"index.js":  "node",
	"main.js":   "node",
	"server.js": "node",
	"tool.js":   "node",
	"index.ts":  "node",
	"main.ts":   "node",
	"server.ts": "node",
	"tool.ts":   "node",
	"main.rb":   "ruby",
	"server.rb": "ruby",
	"tool.rb":   "ruby",
	"tool.sh":   "shell",
	"run.sh":    "shell",
	"main.sh":   "shell",
}

// FindTools walks repoRoot and returns all discovered agent tool entrypoints.
func FindTools(repoRoot string) ([]Tool, error) {
	var tools []Tool

	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}

		name := d.Name()

		if d.IsDir() {
			if skipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}

		if isTestFile(name) {
			return nil
		}

		rel, _ := filepath.Rel(repoRoot, path)
		rel = filepath.ToSlash(rel)

		ext := filepath.Ext(name)

		// Name-based detection (no file read needed).
		if lang, ok := entrypointNames[name]; ok {
			tools = append(tools, Tool{Path: rel, Language: lang})
			return nil
		}

		// Content-based detection for Go, Python, Ruby, Shell.
		switch ext {
		case ".go", ".py", ".rb", ".sh", ".bash":
			src, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			body := string(src)
			switch ext {
			case ".go":
				// Anchor to line boundaries to avoid matching string literals that
				// contain these tokens (e.g. in the discover package itself).
				lined := "\n" + body
				if strings.Contains(lined, "\npackage main\n") && strings.Contains(lined, "\nfunc main()") {
					tools = append(tools, Tool{Path: rel, Language: "go"})
				}
			case ".py":
				hasMain := strings.Contains(body, `if __name__ == "__main__"`) ||
					strings.Contains(body, "if __name__ == '__main__'")
				if hasMain && hasAgentImport(body) {
					tools = append(tools, Tool{Path: rel, Language: "python"})
				}
			case ".rb":
				lines := strings.SplitN(body, "\n", 2)
				if len(lines) > 0 && strings.HasPrefix(lines[0], "#!/usr/bin/env ruby") {
					tools = append(tools, Tool{Path: rel, Language: "ruby"})
				}
			case ".sh", ".bash":
				// Any shell script with a bash/sh shebang is treated as a tool.
				lines := strings.SplitN(body, "\n", 2)
				if len(lines) > 0 {
					first := lines[0]
					if strings.HasPrefix(first, "#!/bin/bash") ||
						strings.HasPrefix(first, "#!/bin/sh") ||
						strings.HasPrefix(first, "#!/usr/bin/env bash") {
						tools = append(tools, Tool{Path: rel, Language: "shell"})
					}
				}
			}
		}

		return nil
	})

	return tools, err
}
