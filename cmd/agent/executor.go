package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

const streamDrainGrace = 100 * time.Millisecond

// executeResponseStream is the common interface for Execute and ExecuteScript streams.
type executeResponseStream interface {
	Send(*pb.ExecuteResponse) error
}

func defaultShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "bash"
}

func buildCommand(shell, command string) *exec.Cmd {
	switch strings.ToLower(shell) {
	case "powershell", "pwsh":
		return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
	case "cmd":
		return exec.Command("cmd.exe", "/C", command)
	case "bash":
		return exec.Command("bash", "-c", command)
	default:
		// Fall back to OS default.
		if runtime.GOOS == "windows" {
			return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
		}
		return exec.Command("bash", "-c", command)
	}
}

func buildScriptCommand(shell, scriptPath string, args []string) *exec.Cmd {
	switch strings.ToLower(shell) {
	case "powershell", "pwsh":
		cmdArgs := append([]string{"-NoProfile", "-NonInteractive", "-File", scriptPath}, args...)
		return exec.Command("powershell.exe", cmdArgs...)
	case "bash":
		cmdArgs := append([]string{scriptPath}, args...)
		return exec.Command("bash", cmdArgs...)
	default:
		if runtime.GOOS == "windows" {
			cmdArgs := append([]string{"-NoProfile", "-NonInteractive", "-File", scriptPath}, args...)
			return exec.Command("powershell.exe", cmdArgs...)
		}
		cmdArgs := append([]string{scriptPath}, args...)
		return exec.Command("bash", cmdArgs...)
	}
}

func applyEnv(cmd *exec.Cmd, env map[string]string) {
	if len(env) == 0 {
		return
	}
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
}

func setDetached(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	setDetachedPlatform(cmd.SysProcAttr)
}

func executeCommand(ctx context.Context, command, shell, workingDir string, env map[string]string, timeoutSec int32, detach bool, stream executeResponseStream) error {
	if shell == "" {
		shell = defaultShell()
	}

	cmd := buildCommand(shell, command)
	if workingDir != "" {
		cmd.Dir = workingDir
	}
	applyEnv(cmd, env)

	if detach {
		setDetached(cmd)
		devNull, err := attachDetachedIO(cmd)
		if err != nil {
			return fmt.Errorf("failed to configure detached stdio: %w", err)
		}
		if err := cmd.Start(); err != nil {
			devNull.Close()
			return fmt.Errorf("failed to start detached process: %w", err)
		}
		devNull.Close()
		stream.Send(&pb.ExecuteResponse{
			Pid:  int32(cmd.Process.Pid),
			Done: true,
		})
		// Release the process so it's not waited on.
		cmd.Process.Release()
		return nil
	}

	return runAndStream(ctx, cmd, timeoutSec, stream)
}

func executeScript(ctx context.Context, scriptBody, shell, workingDir string, env map[string]string, timeoutSec int32, args []string, stream executeResponseStream) error {
	if shell == "" {
		shell = defaultShell()
	}

	// Write script to temp file.
	ext := ".sh"
	if strings.ToLower(shell) == "powershell" || strings.ToLower(shell) == "pwsh" {
		ext = ".ps1"
	} else if strings.ToLower(shell) == "cmd" {
		ext = ".cmd"
	}

	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("lablink-script-%d%s", time.Now().UnixNano(), ext))
	if err := os.WriteFile(tmpFile, []byte(scriptBody), 0755); err != nil {
		return fmt.Errorf("failed to write temp script: %w", err)
	}
	defer os.Remove(tmpFile)

	cmd := buildScriptCommand(shell, tmpFile, args)
	if workingDir != "" {
		cmd.Dir = workingDir
	}
	applyEnv(cmd, env)

	return runAndStream(ctx, cmd, timeoutSec, stream)
}

func runAndStream(ctx context.Context, cmd *exec.Cmd, timeoutSec int32, stream executeResponseStream) error {
	if timeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
		defer cancel()
	}

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		stdoutReader.Close()
		stdoutWriter.Close()
		return fmt.Errorf("stderr pipe: %w", err)
	}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter

	if err := cmd.Start(); err != nil {
		stdoutReader.Close()
		stdoutWriter.Close()
		stderrReader.Close()
		stderrWriter.Close()
		return fmt.Errorf("failed to start: %w", err)
	}
	stdoutWriter.Close()
	stderrWriter.Close()

	// Send PID in first message.
	stream.Send(&pb.ExecuteResponse{Pid: int32(cmd.Process.Pid)})

	// Stream stdout and stderr concurrently.
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errCh <- streamPipe(stdoutReader, pb.ExecuteResponse_STDOUT, stream)
	}()
	go func() {
		defer wg.Done()
		errCh <- streamPipe(stderrReader, pb.ExecuteResponse_STDERR, stream)
	}()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var exitCode int
	select {
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		exitCode = -1
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
	}

	// Give readers a brief chance to drain buffered output after the process exits.
	// If a spawned child inherited the handles, close the read side so we don't
	// hang on descendants that outlive the command we were asked to run.
	waitForStreamReaders(&wg, stdoutReader, stderrReader)
	close(errCh)

	for streamErr := range errCh {
		if streamErr != nil && !isBenignStreamError(streamErr) {
			stream.Send(&pb.ExecuteResponse{
				Stream: pb.ExecuteResponse_STDERR,
				Data:   []byte(fmt.Sprintf("[lablink] stream error: %v\n", streamErr)),
			})
			exitCode = -1
		}
	}

	stream.Send(&pb.ExecuteResponse{
		Done:     true,
		ExitCode: int32(exitCode),
	})
	return nil
}

func waitForStreamReaders(wg *sync.WaitGroup, readers ...io.Closer) {
	readersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(readersDone)
	}()

	timer := time.NewTimer(streamDrainGrace)
	defer timer.Stop()

	select {
	case <-readersDone:
	case <-timer.C:
		for _, reader := range readers {
			_ = reader.Close()
		}
		<-readersDone
	}

	for _, reader := range readers {
		_ = reader.Close()
	}
}

func streamPipe(r io.Reader, streamType pb.ExecuteResponse_Stream, stream executeResponseStream) error {
	reader := bufio.NewReader(r)
	for {
		data, err := reader.ReadBytes('\n')
		if len(data) > 0 {
			stream.Send(&pb.ExecuteResponse{
				Stream: streamType,
				Data:   append([]byte(nil), data...),
			})
		}
		if err == nil {
			continue
		}
		if err == io.EOF {
			return nil
		}
		return err
	}
}

func isBenignStreamError(err error) bool {
	return errors.Is(err, os.ErrClosed)
}

func attachDetachedIO(cmd *exec.Cmd) (*os.File, error) {
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	return devNull, nil
}
