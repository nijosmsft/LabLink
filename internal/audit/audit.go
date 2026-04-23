package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nijosmsft/lablink/internal/flock"
)

const (
	maxLogSize  = 10 * 1024 * 1024 // 10MB
	logFileName = "history.jsonl"
)

// Entry represents a single audit log entry.
type Entry struct {
	Timestamp   time.Time `json:"ts"`
	Node        string    `json:"node"`
	Tool        string    `json:"tool"`
	Command     string    `json:"command"`
	Shell       string    `json:"shell,omitempty"`
	ExitCode    int       `json:"exit_code"`
	DurationMs  int64     `json:"duration_ms"`
	OutputBytes int       `json:"output_bytes"`
	Truncated   bool      `json:"truncated"`
}

// Log is an append-only audit logger.
//
// The in-process mutex serialises writers within one LabLinkServer process;
// the OS-level lock on a sidecar file serialises across processes so that
// rotation (rename of history.jsonl -> history.1.jsonl) and concurrent
// appends from a sibling LabLinkServer cannot interleave or lose lines.
type Log struct {
	mu      sync.Mutex
	dirPath string
}

// NewLog creates a new audit logger writing to the given directory.
func NewLog(dirPath string) *Log {
	return &Log{dirPath: dirPath}
}

func (l *Log) logPath() string {
	return filepath.Join(l.dirPath, logFileName)
}

func (l *Log) lockPath() string {
	return filepath.Join(l.dirPath, logFileName+".lock")
}

// Append writes an entry to the audit log.
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(l.dirPath, 0755); err != nil {
		return err
	}

	lk, err := flock.Lock(l.lockPath())
	if err != nil {
		return fmt.Errorf("acquire audit lock: %w", err)
	}
	defer lk.Close()

	if info, err := os.Stat(l.logPath()); err == nil && info.Size() > maxLogSize {
		rotated := filepath.Join(l.dirPath, "history.1.jsonl")
		os.Remove(rotated)
		os.Rename(l.logPath(), rotated)
	}

	data, err := json.Marshal(e)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(l.logPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s\n", data)
	return err
}

// Query returns recent entries matching the filters.
func (l *Log) Query(node string, commandFilter string, lastN int) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Take the cross-process lock to ensure we don't read mid-rotation
	// (rename + new append from a sibling process). It's fine if the lock
	// can't be created (e.g. dir missing) — we just attempt the read.
	if lk, err := flock.Lock(l.lockPath()); err == nil {
		defer lk.Close()
	}

	data, err := os.ReadFile(l.logPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var all []Entry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if node != "" && e.Node != node {
			continue
		}
		if commandFilter != "" && !strings.Contains(e.Command, commandFilter) {
			continue
		}
		all = append(all, e)
	}

	if lastN > 0 && len(all) > lastN {
		all = all[len(all)-lastN:]
	}
	return all, nil
}
