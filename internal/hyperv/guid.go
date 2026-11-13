package hyperv

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

func validateGUID(kind, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if _, err := uuid.Parse(value); err != nil {
		return fmt.Errorf("%s GUID %q is invalid", kind, value)
	}
	return nil
}

func normalizedGUIDOrEmpty(value string) string {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.String())
}
