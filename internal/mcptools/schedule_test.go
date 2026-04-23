package mcptools

import (
	"testing"

	"github.com/nijosmsft/lablink/internal/registry"
)

func TestBuildScheduledCommandHonorsShell(t *testing.T) {
	tests := []struct {
		name        string
		shell       string
		command     string
		wantShell   string
		wantCommand string
	}{
		{
			name:        "powershell",
			shell:       "powershell",
			command:     "Write-Host hi",
			wantShell:   "powershell",
			wantCommand: "Start-Sleep -Seconds 5; Write-Host hi",
		},
		{
			name:        "cmd",
			shell:       "cmd",
			command:     "echo hi",
			wantShell:   "cmd",
			wantCommand: "timeout /t 5 /nobreak >NUL & echo hi",
		},
		{
			name:        "bash",
			shell:       "bash",
			command:     "echo hi",
			wantShell:   "bash",
			wantCommand: "sleep 5; echo hi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotShell, gotCommand, err := buildScheduledCommand(tt.shell, 5, tt.command)
			if err != nil {
				t.Fatalf("buildScheduledCommand returned error: %v", err)
			}
			if gotShell != tt.wantShell {
				t.Fatalf("shell = %q, want %q", gotShell, tt.wantShell)
			}
			if gotCommand != tt.wantCommand {
				t.Fatalf("command = %q, want %q", gotCommand, tt.wantCommand)
			}
		})
	}
}

func TestBuildScheduledCommandRejectsUnsupportedShell(t *testing.T) {
	if _, _, err := buildScheduledCommand("fish", 5, "echo hi"); err == nil {
		t.Fatal("expected unsupported shell error")
	}
}

func TestDefaultScheduleShellUsesNodeOS(t *testing.T) {
	if got := defaultScheduleShell(&registry.Node{OS: "windows"}); got != "powershell" {
		t.Fatalf("windows default shell = %q", got)
	}
	if got := defaultScheduleShell(&registry.Node{OS: "linux"}); got != "bash" {
		t.Fatalf("linux default shell = %q", got)
	}
}
