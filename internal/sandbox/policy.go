package sandbox

import (
	"os"
)

func writeTempPolicy(content string) (string, error) {
	f, err := os.CreateTemp("", "autofix-policy-*.yaml")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return "", err
	}
	return f.Name(), nil
}
