package winpath

import (
	"fmt"
	"strings"
)

// CleanAbsolute validates and normalizes an absolute Windows path without
// depending on the operating system running lablink-server.
func CleanAbsolute(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("Windows path is required")
	}
	if strings.Contains(value, "/") {
		return "", fmt.Errorf("Windows path %q must use backslashes", value)
	}

	root, rest, err := splitRoot(value)
	if err != nil {
		return "", err
	}
	if rest == "" {
		if strings.HasPrefix(root, `\\`) {
			return strings.TrimSuffix(root, `\`), nil
		}
		return root, nil
	}
	parts := strings.Split(rest, `\`)
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		if err := validateComponent(part); err != nil {
			return "", fmt.Errorf("Windows path %q: %w", value, err)
		}
		clean = append(clean, part)
	}
	return root + strings.Join(clean, `\`), nil
}

func Join(root string, elements ...string) (string, error) {
	cleanRoot, err := CleanAbsolute(root)
	if err != nil {
		return "", err
	}
	result := strings.TrimSuffix(cleanRoot, `\`)
	for _, element := range elements {
		if strings.Contains(element, `\`) {
			return "", fmt.Errorf("invalid Windows path component %q", element)
		}
		if err := validateComponent(element); err != nil {
			return "", err
		}
		result += `\` + element
	}
	return result, nil
}

func splitRoot(value string) (string, string, error) {
	if len(value) >= 3 && isASCIIAlpha(value[0]) && value[1] == ':' && value[2] == '\\' {
		root := value[:3]
		rest := value[3:]
		if rest == "" {
			return root, "", nil
		}
		return root, rest, nil
	}
	if strings.HasPrefix(value, `\\`) {
		rest := strings.TrimPrefix(value, `\\`)
		parts := strings.SplitN(rest, `\`, 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("UNC path %q must include server and share", value)
		}
		if err := validateComponent(parts[0]); err != nil {
			return "", "", fmt.Errorf("UNC server: %w", err)
		}
		if err := validateComponent(parts[1]); err != nil {
			return "", "", fmt.Errorf("UNC share: %w", err)
		}
		root := `\\` + parts[0] + `\` + parts[1] + `\`
		if len(parts) == 2 {
			return root, "", nil
		}
		return root, parts[2], nil
	}
	return "", "", fmt.Errorf("Windows path %q must be drive-absolute or UNC", value)
}

func validateComponent(value string) error {
	if value == "" || value == "." || value == ".." || strings.ContainsAny(value, `/<>:"|?*`) ||
		strings.TrimRight(value, " .") != value {
		return fmt.Errorf("invalid Windows path component %q", value)
	}
	for _, r := range value {
		if r < 0x20 {
			return fmt.Errorf("invalid Windows path component %q", value)
		}
	}
	return nil
}

func isASCIIAlpha(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
