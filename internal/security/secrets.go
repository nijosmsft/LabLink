package security

import (
	"fmt"
	"os"
	"strings"
)

// FirstNonEmpty returns the first non-empty, trimmed value.
func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// FirstPresentEnv returns the first non-empty environment variable value.
func FirstPresentEnv(names ...string) string {
	value, _ := firstPresentEnv(names...)
	return value
}

// ReadSecretFile reads a text secret from disk and trims trailing whitespace.
func ReadSecretFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return value, nil
}

// ResolveToken resolves a shared auth token from explicit values, then
// environment variables, then token files referenced by environment variables.
func ResolveToken(explicitValue, explicitFile string, envValueNames, envFileNames []string) (string, string, error) {
	if value := FirstNonEmpty(explicitValue); value != "" {
		return value, "command-line flag", nil
	}

	if path := FirstNonEmpty(explicitFile); path != "" {
		value, err := ReadSecretFile(path)
		if err != nil {
			return "", "", fmt.Errorf("read auth token file %s: %w", path, err)
		}
		return value, fmt.Sprintf("file %s", path), nil
	}

	if value, name := firstPresentEnv(envValueNames...); name != "" {
		return value, name + " env var", nil
	}

	if path, name := firstPresentEnv(envFileNames...); name != "" {
		value, err := ReadSecretFile(path)
		if err != nil {
			return "", "", fmt.Errorf("read auth token file from %s (%s): %w", name, path, err)
		}
		return value, fmt.Sprintf("%s -> %s", name, path), nil
	}

	return "", "none", nil
}

func firstPresentEnv(names ...string) (string, string) {
	for _, name := range names {
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed, name
		}
	}
	return "", ""
}
