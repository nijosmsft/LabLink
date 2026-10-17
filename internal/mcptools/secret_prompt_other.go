//go:build !windows

package mcptools

import (
	"context"
	"fmt"
)

func launchSecretPrompt(_ context.Context, _, _, _ string) error {
	return fmt.Errorf("automatic local secret prompting is currently supported only on Windows")
}
