package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadEnvFixtures reads a dotenv-style file: one KEY=value per line,
// '#'-prefixed comments and blank lines skipped. Values are used verbatim
// (not shell-unescaped) — quote handling, if any, is the caller's file to
// write correctly. A malformed line (no '=') is a hard error, matching
// policy.LoadDenyList's fail-fast convention: a fixtures file that silently
// doesn't load is a worse failure mode than refusing to run.
func LoadEnvFixtures(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open env fixtures: %w", err)
	}
	defer f.Close()

	fixtures := map[string]string{}
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY=value, got %q", path, lineNum, line)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("%s:%d: empty key", path, lineNum)
		}
		fixtures[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read env fixtures: %w", err)
	}
	return fixtures, nil
}
