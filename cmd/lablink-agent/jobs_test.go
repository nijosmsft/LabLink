package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

func newTestManager(t *testing.T) *JobManager {
	t.Helper()
	dir := t.TempDir()
	m, err := NewJobManager(filepath.Join(dir, "jobs"), 0)
	if err != nil {
		t.Fatalf("NewJobManager: %v", err)
	}
	setJobManager(m)
	return m
}

func echoCmd(text string) (cmd, shell string) {
	if runtime.GOOS == "windows" {
		return "Write-Host " + text, "powershell"
	}
	return "echo " + text, "bash"
}

// waitForStatus polls the manager until the job reaches a terminal state or
// timeout expires.
func waitForStatus(t *testing.T, m *JobManager, id string, want pb.JobStatus, timeout time.Duration) *pb.Job {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		job, err := m.Get(id)
		if err == nil && job.Status == want {
			return job
		}
		time.Sleep(50 * time.Millisecond)
	}
	job, _ := m.Get(id)
	t.Fatalf("job %s did not reach %v within %v (current=%v)", id, want, timeout, job.GetStatus())
	return nil
}

func TestJobStartAndCompleteEmitsTerminalMeta(t *testing.T) {
	m := newTestManager(t)
	cmd, shell := echoCmd("hello-lablink-jobs")
	job, err := m.Start(cmd, shell, "", nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if job.JobId == "" || job.Status != pb.JobStatus_JOB_STATUS_RUNNING {
		t.Fatalf("unexpected initial meta: %+v", job)
	}
	final := waitForStatus(t, m, job.JobId, pb.JobStatus_JOB_STATUS_EXITED, 30*time.Second)
	if final.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d (err=%q)", final.ExitCode, final.Error)
	}
	if final.EndedAt == "" {
		t.Errorf("ended_at should be set")
	}
	// Output captured on disk.
	out, err := m.GetOutput(job.JobId, pb.GetJobOutputRequest_STDOUT, 0, 0)
	if err != nil {
		t.Fatalf("GetOutput: %v", err)
	}
	if !strings.Contains(string(out.Stdout), "hello-lablink-jobs") {
		t.Errorf("stdout did not contain marker: %q", string(out.Stdout))
	}
}

func TestJobCancelTerminatesRunningProcess(t *testing.T) {
	m := newTestManager(t)
	var cmd, shell string
	if runtime.GOOS == "windows" {
		cmd, shell = "Start-Sleep -Seconds 30", "powershell"
	} else {
		cmd, shell = "sleep 30", "bash"
	}
	job, err := m.Start(cmd, shell, "", nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Give the child a moment to actually enter the sleep.
	time.Sleep(200 * time.Millisecond)
	if _, err := m.Cancel(job.JobId, true); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	final := waitForStatus(t, m, job.JobId, pb.JobStatus_JOB_STATUS_CANCELED, 10*time.Second)
	if final.EndedAt == "" {
		t.Errorf("ended_at should be set after cancel")
	}
}

func TestJobSubscribeReceivesLifecycleEvents(t *testing.T) {
	m := newTestManager(t)
	ch, unsub := m.Subscribe()
	defer unsub()

	cmd, shell := echoCmd("subscriber-test")
	job, err := m.Start(cmd, shell, "", nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	sawStarted, sawCompleted := false, false
	deadline := time.After(30 * time.Second)
	for !(sawStarted && sawCompleted) {
		select {
		case ev := <-ch:
			if ev == nil {
				t.Fatalf("channel closed before completion")
			}
			if ev.Job.GetJobId() != job.JobId {
				continue
			}
			switch ev.Kind {
			case pb.JobEvent_STARTED:
				sawStarted = true
			case pb.JobEvent_COMPLETED:
				sawCompleted = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for events (started=%v completed=%v)", sawStarted, sawCompleted)
		}
	}
}

func TestJobDeleteRequiresTerminalState(t *testing.T) {
	m := newTestManager(t)
	var cmd, shell string
	if runtime.GOOS == "windows" {
		cmd, shell = "Start-Sleep -Seconds 30", "powershell"
	} else {
		cmd, shell = "sleep 30", "bash"
	}
	job, err := m.Start(cmd, shell, "", nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := m.Delete(job.JobId); err == nil {
		t.Errorf("expected error deleting running job")
	}
	_, _ = m.Cancel(job.JobId, true)
	waitForStatus(t, m, job.JobId, pb.JobStatus_JOB_STATUS_CANCELED, 10*time.Second)
	ok, err := m.Delete(job.JobId)
	if err != nil {
		t.Fatalf("Delete after cancel: %v", err)
	}
	if !ok {
		t.Errorf("Delete should report true")
	}
	// Directory should be gone.
	m2, err := NewJobManager(m.root, 0)
	if err != nil {
		t.Fatal(err)
	}
	m2.Recover()
	if _, err := m2.Get(job.JobId); err != ErrJobNotFound {
		t.Errorf("expected ErrJobNotFound after delete+recover, got %v", err)
	}
}

func TestJobRecoverMarksOrphanedWhenPidGone(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "jobs")
	// Hand-craft a running-meta pointing at a PID that definitely does not
	// exist. PID 0x7fffffff is reserved-ish on Windows and invalid on Linux.
	jobID := "20240101T000000Z-abcdef"
	jobDir := filepath.Join(root, jobID)
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := &pb.Job{
		JobId:     jobID,
		Command:   "sleep 1",
		Shell:     "bash",
		Pid:       0x7fffffff,
		Status:    pb.JobStatus_JOB_STATUS_RUNNING,
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := saveMeta(jobDir, meta); err != nil {
		t.Fatal(err)
	}

	m, err := NewJobManager(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	m.Recover()
	got, err := m.Get(jobID)
	if err != nil {
		t.Fatalf("Get after recover: %v", err)
	}
	if got.Status != pb.JobStatus_JOB_STATUS_ORPHANED {
		t.Errorf("expected ORPHANED, got %v", got.Status)
	}
	if got.EndedAt == "" {
		t.Errorf("ended_at should be populated on recovery")
	}
}

func TestIsValidJobIDRejectsPathTraversal(t *testing.T) {
	cases := map[string]bool{
		"20240101T000000Z-abcdef": true,
		"":                        false,
		"../etc":                  false,
		"a/b":                     false,
		"a\\b":                    false,
		"has space":               false,
		strings.Repeat("x", 65):   false,
	}
	for input, want := range cases {
		if got := isValidJobID(input); got != want {
			t.Errorf("isValidJobID(%q) = %v, want %v", input, got, want)
		}
	}
}
