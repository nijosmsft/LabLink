package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

type testExecuteStream struct {
	mu        sync.Mutex
	responses []*pb.ExecuteResponse
}

func (s *testExecuteStream) Send(resp *pb.ExecuteResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	clone := &pb.ExecuteResponse{
		Stream:   resp.Stream,
		Done:     resp.Done,
		ExitCode: resp.ExitCode,
		Pid:      resp.Pid,
	}
	if len(resp.Data) > 0 {
		clone.Data = append([]byte(nil), resp.Data...)
	}
	s.responses = append(s.responses, clone)
	return nil
}

func sleepCommand(seconds int) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return buildCommand("powershell", fmt.Sprintf("Start-Sleep -Seconds %d", seconds))
	}
	return buildCommand("bash", fmt.Sprintf("sleep %d", seconds))
}

func infiniteCommand() (shell string, command string) {
	if runtime.GOOS == "windows" {
		return "powershell", "while($true) { Start-Sleep -Seconds 1 }"
	}
	return "bash", "while true; do sleep 1; done"
}

func combinedStreamOutput(responses []*pb.ExecuteResponse) string {
	var buf bytes.Buffer
	for _, resp := range responses {
		buf.Write(resp.Data)
	}
	return buf.String()
}

func powershellLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func TestRunAndStreamHonorsTimeout(t *testing.T) {
	stream := &testExecuteStream{}
	start := time.Now()

	err := runAndStream(context.Background(), sleepCommand(10), 1, stream)
	if err != nil {
		t.Fatalf("runAndStream returned error: %v", err)
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("runAndStream exceeded timeout window: %v", elapsed)
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()

	if len(stream.responses) == 0 {
		t.Fatal("expected at least one response")
	}

	last := stream.responses[len(stream.responses)-1]
	if !last.Done {
		t.Fatal("expected final response to mark completion")
	}
	if last.ExitCode != -1 {
		t.Fatalf("expected timeout exit code -1, got %d", last.ExitCode)
	}
}

func TestExecuteCommandHonorsTimeoutForInfiniteLoop(t *testing.T) {
	stream := &testExecuteStream{}
	shell, command := infiniteCommand()
	start := time.Now()

	err := executeCommand(context.Background(), command, shell, "", nil, 1, false, stream)
	if err != nil {
		t.Fatalf("executeCommand returned error: %v", err)
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("executeCommand exceeded timeout window: %v", elapsed)
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()

	if len(stream.responses) == 0 {
		t.Fatal("expected at least one response")
	}

	last := stream.responses[len(stream.responses)-1]
	if !last.Done {
		t.Fatal("expected final response to mark completion")
	}
	if last.ExitCode != -1 {
		t.Fatalf("expected timeout exit code -1, got %d", last.ExitCode)
	}
}

func TestExecuteCommandStartProcessWithRedirectsReturnsCleanly(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-specific Start-Process behavior")
	}

	stream := &testExecuteStream{}
	tempDir, err := os.MkdirTemp("", "di-executor-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() {
		time.Sleep(2 * time.Second)
		_ = os.RemoveAll(tempDir)
	})
	stdoutPath := filepath.Join(tempDir, "child-out.txt")
	stderrPath := filepath.Join(tempDir, "child-err.txt")
	command := fmt.Sprintf(
		"$out = '%s'; $err = '%s'; Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile -Command \"Start-Sleep -Milliseconds 500\"' -RedirectStandardOutput $out -RedirectStandardError $err",
		powershellLiteral(stdoutPath),
		powershellLiteral(stderrPath),
	)
	start := time.Now()

	err = executeCommand(context.Background(), command, "powershell", "", nil, 10, false, stream)
	if err != nil {
		t.Fatalf("executeCommand returned error: %v", err)
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("executeCommand took too long to return: %v", elapsed)
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()

	if len(stream.responses) == 0 {
		t.Fatal("expected at least one response")
	}

	last := stream.responses[len(stream.responses)-1]
	if !last.Done {
		t.Fatal("expected final response to mark completion")
	}
	if last.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d; output=%q", last.ExitCode, combinedStreamOutput(stream.responses))
	}

	if output := combinedStreamOutput(stream.responses); strings.Contains(output, "[lablink] stream error:") {
		t.Fatalf("unexpected stream error in output: %q", output)
	}
}

func TestStreamPipeHandlesLongLines(t *testing.T) {
	stream := &testExecuteStream{}
	longLine := append(bytes.Repeat([]byte("a"), 2*1024*1024), '\n')

	if err := streamPipe(bytes.NewReader(longLine), pb.ExecuteResponse_STDOUT, stream); err != nil {
		t.Fatalf("streamPipe returned error: %v", err)
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()

	if len(stream.responses) != 1 {
		t.Fatalf("expected 1 streamed chunk, got %d", len(stream.responses))
	}
	if !bytes.Equal(stream.responses[0].Data, longLine) {
		t.Fatalf("streamed payload length = %d, want %d", len(stream.responses[0].Data), len(longLine))
	}
}
