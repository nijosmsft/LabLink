package mcptools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// executeLocalPowershell runs a PowerShell script locally and returns the output.
func executeLocalPowershell(ctx context.Context, script string, timeoutSec int) (string, int, int, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pwsh", "-NoProfile", "-Command", script)
	output, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return string(output), exitCode, 0, nil
}
