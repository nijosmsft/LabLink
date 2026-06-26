package mcptools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nijosmsft/lablink/internal/healthmon"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

// hmon is the global health monitor reference, set by SetHealthMonitor.
var hmon *healthmon.Monitor

// SetHealthMonitor stores the health monitor for use by all tool handlers.
func SetHealthMonitor(m *healthmon.Monitor) {
	hmon = m
}

// nodeCallContext returns a context for gRPC calls to a node.
// If the health monitor is active, the context is cancelled when either
// the parent context or the node's health context is cancelled (node goes dead).
// If the node is already known to be offline, returns an already-cancelled context
// so the call fails immediately instead of waiting for gRPC dial timeout.
func nodeCallContext(parentCtx context.Context, nodeName string) (context.Context, context.CancelFunc) {
	if hmon == nil {
		return parentCtx, func() {}
	}

	// Fail fast only for nodes known to be offline. Unknown nodes (for example,
	// just-registered nodes or nodes before the next health probe) should still
	// get a live context so callers can attempt the RPC immediately.
	status := hmon.GetStatus(nodeName)
	if status.Status == "offline" {
		ctx, cancel := context.WithCancel(parentCtx)
		cancel() // immediately cancelled
		return ctx, func() {}
	}

	nodeCtx := hmon.NodeContext(nodeName)
	return mergeContexts(parentCtx, nodeCtx)
}

func timeNow() time.Time {
	return time.Now()
}

// mergeContexts returns a context that is cancelled when either parent is cancelled.
// Used to combine the MCP request context with the health monitor's node context.
func mergeContexts(ctx1, ctx2 context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx1)
	go func() {
		select {
		case <-ctx2.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func baseName(path string) string {
	return filepath.Base(path)
}

func nodeHost(address string) string {
	if i := strings.LastIndex(address, ":"); i >= 0 {
		return address[:i]
	}
	return address
}

func nodePort(address string) string {
	if i := strings.LastIndex(address, ":"); i >= 0 {
		return address[i+1:]
	}
	return "9091"
}

// executeAndCollect runs a command on a remote node via gRPC and returns the output.
func executeAndCollect(ctx context.Context, client pb.NodeAgentClient, command, shell, workingDir string, env map[string]string, timeoutSec int32) (string, int, int, error) {
	stream, err := client.Execute(ctx, &pb.ExecuteRequest{
		Command:        command,
		Shell:          shell,
		WorkingDir:     workingDir,
		Env:            env,
		TimeoutSeconds: timeoutSec,
	})
	if err != nil {
		return "", -1, 0, err
	}
	out, exit, pid, _, err := collectStreamOutput(stream)
	return out, exit, pid, err
}

// pushFileToNode pushes a local file to a remote node. Returns bytes written.
func pushFileToNode(ctx context.Context, client pb.NodeAgentClient, localPath, remotePath string) (int64, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", localPath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}

	stream, err := client.PushFile(ctx)
	if err != nil {
		return 0, err
	}

	resp, err := sendLocalFile(stream, f, info.Size(), remotePath)
	if err != nil {
		return 0, err
	}
	return resp.BytesWritten, nil
}

// localPowershellExe returns the PowerShell executable to use for the
// localhost target. On Windows we use Windows PowerShell (powershell.exe) for
// parity with the remote agent and the Hyper-V cmdlet behavior (OQ-3); on
// other OSes we fall back to pwsh.
func localPowershellExe() string {
	if runtime.GOOS == "windows" {
		return "powershell.exe"
	}
	return "pwsh"
}

// executeLocalPowershell runs a PowerShell script locally and returns the
// output. timeoutSec <= 0 means "no timeout" (parity with the remote agent's
// TimeoutSeconds=0 semantics). A launch failure returns a non-nil error; a
// nonzero process exit is reported via the returned exit code (callers/runPS
// treat a nonzero exit as a tool failure).
func executeLocalPowershell(ctx context.Context, script string, timeoutSec int) (string, int, int, error) {
	if timeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, localPowershellExe(), "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Process ran and exited nonzero; surface the exit code, not a Go error.
			return string(output), exitErr.ExitCode(), 0, nil
		}
		// Launch/context failure (binary missing, timeout, etc.).
		return string(output), -1, 0, err
	}
	return string(output), 0, 0, nil
}
