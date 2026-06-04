package main

import (
	"os"
	"path/filepath"
	"runtime"
)

// agentDataDir returns the root directory the agent uses for persistent
// state (background job records, etc.).
//
// Resolution order:
//  1. LABLINK_AGENT_DATA env var (absolute path).
//  2. Platform default:
//     - Windows: %ProgramData%\LabLink\agent
//     - Linux/macOS: /var/lib/lablink-agent  (falls back to ~/.lablink/agent
//       when the system path is not writable, e.g. unprivileged runs).
func agentDataDir() string {
	if v := os.Getenv("LABLINK_AGENT_DATA"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "LabLink", "agent")
	}
	// On Unix-like systems prefer /var/lib when we can write there, else fall
	// back to the user's home. The agent typically runs as root via a service
	// manager; dev runs without sudo should still work.
	const sys = "/var/lib/lablink-agent"
	if err := os.MkdirAll(sys, 0o755); err == nil {
		return sys
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".lablink", "agent")
	}
	return sys
}

// jobsDir returns the directory where background job records live.
func jobsDir() string {
	return filepath.Join(agentDataDir(), "jobs")
}
