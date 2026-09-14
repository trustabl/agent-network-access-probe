// Package class loads a hand-written agent-class manifest: the list of tools
// that make up an agent's grant set, so Probe can scan every one of them and
// union their observed egress into a single least-privilege policy.
package class

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Member is one tool in an agent class. Path is required — it names a
// directory containing the tool. Entrypoint is an optional override for
// when auto-discovery inside Path is ambiguous; when empty, the caller is
// expected to auto-discover the entrypoint(s) inside Path the same way
// `--source` with no `--entrypoint` already does.
type Member struct {
	Path       string `yaml:"path"`
	Entrypoint string `yaml:"entrypoint,omitempty"`
	BaseImage  string `yaml:"base_image,omitempty"`
}

// Class is a named agent class and the tools it's allowed to invoke.
type Class struct {
	Name  string   `yaml:"class"`
	Tools []Member `yaml:"tools"`
}

// Load reads and validates a class YAML file.
func Load(path string) (*Class, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read class file: %w", err)
	}
	var c Class
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse class file: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Class) validate() error {
	if c.Name == "" {
		return fmt.Errorf("class file: %q is required", "class")
	}
	if len(c.Tools) == 0 {
		return fmt.Errorf("class %q: at least one tool is required under %q", c.Name, "tools")
	}
	seen := map[string]bool{}
	for i, m := range c.Tools {
		if m.Path == "" {
			return fmt.Errorf("class %q: tools[%d] is missing %q", c.Name, i, "path")
		}
		info, err := os.Stat(m.Path)
		if err != nil {
			return fmt.Errorf("class %q: tools[%d] path %q: %w", c.Name, i, m.Path, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("class %q: tools[%d] path %q is not a directory", c.Name, i, m.Path)
		}
		key := m.Path + "::" + m.Entrypoint
		if seen[key] {
			return fmt.Errorf("class %q: duplicate tool entry for path %q entrypoint %q", c.Name, m.Path, m.Entrypoint)
		}
		seen[key] = true
	}
	return nil
}
