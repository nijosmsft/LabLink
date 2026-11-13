//go:build windows

package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

const secretConsoleEnv = "LABLINK_SECRET_NEW_CONSOLE"
const secretStatusFileEnv = "LABLINK_SECRET_STATUS_FILE"

type secretPromptStatus struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func launchSecretPrompt(ctx context.Context, helperPath, storePath, name string) error {
	return launchLocalSecretPrompt(ctx, helperPath, storePath, name, "")
}

func launchCredentialPrompt(
	ctx context.Context,
	helperPath, storePath, secretName, credentialName string,
) error {
	return launchLocalSecretPrompt(
		ctx, helperPath, storePath, secretName,
		fmt.Sprintf("Password for credential %q", credentialName),
	)
}

func launchLocalSecretPrompt(
	ctx context.Context,
	helperPath, storePath, name, label string,
) error {
	info, err := os.Stat(helperPath)
	if err != nil {
		return fmt.Errorf("locate helper %q: %w", helperPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("secret helper path is a directory: %s", helperPath)
	}

	statusFile, err := os.CreateTemp("", "lablink-secret-status-*.json")
	if err != nil {
		return fmt.Errorf("create helper status file: %w", err)
	}
	statusPath := statusFile.Name()
	if err := statusFile.Close(); err != nil {
		_ = os.Remove(statusPath)
		return fmt.Errorf("close helper status file: %w", err)
	}
	defer os.Remove(statusPath)

	args := []string{"set", "--store", storePath}
	if label != "" {
		args = append(args, "--label", label)
	}
	args = append(args, name)
	cmd := exec.CommandContext(ctx, helperPath, args...)
	cmd.Env = append(
		os.Environ(),
		secretConsoleEnv+"=1",
		secretStatusFileEnv+"="+statusPath,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_CONSOLE,
	}
	runErr := cmd.Run()
	status, statusErr := readSecretPromptStatus(statusPath)
	if statusErr == nil && status.Error != "" {
		return errors.New(status.Error)
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return fmt.Errorf("helper exited with status %d", exitErr.ExitCode())
		}
		return runErr
	}
	if statusErr != nil {
		return statusErr
	}
	if !status.OK {
		return fmt.Errorf("helper did not report success")
	}
	return nil
}

func readSecretPromptStatus(path string) (secretPromptStatus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return secretPromptStatus{}, fmt.Errorf("read helper status: %w", err)
	}
	var status secretPromptStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return secretPromptStatus{}, fmt.Errorf("parse helper status: %w", err)
	}
	return status, nil
}
