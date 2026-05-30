package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

// Defaults for output retrieval. Browsers and MCP clients rarely want a
// multi-MB blob inline, so we cap aggressively by default but allow callers
// to raise it up to a hard ceiling.
const (
	defaultOutputBytes = 1 << 20 // 1 MiB
	maxOutputBytes     = 8 << 20 // 8 MiB
	defaultListLimit   = 50
	maxListLimit       = 500
	defaultRetention   = 7 * 24 * time.Hour
)

// jobEntry is the in-memory tracker for a single background job.
type jobEntry struct {
	mu sync.Mutex
	// meta is the canonical state snapshot persisted to meta.json. The
	// manager treats this as immutable from outside; internal updates always
	// happen through the entry's methods.
	meta *pb.Job
	// dir is the filesystem directory holding meta.json, stdout.log, stderr.log.
	dir string
	// proc is set while the tracker goroutine is alive. After cmd.Wait()
	// returns — or after a process recovered on startup — it may be nil.
	proc *os.Process
	// stdoutFile / stderrFile are open while the child is running so we can
	// close them cleanly on exit.
	stdoutFile *os.File
	stderrFile *os.File
	// live indicates a tracker goroutine is watching this process.
	live bool
	// done is closed by the tracker once the process has been waited on,
	// file handles are closed, and terminal meta is persisted. Operations
	// that need the filesystem quiesced (Cancel return, Delete) wait on
	// this channel. nil for recovered jobs without a live tracker.
	done chan struct{}
}

// JobManager owns the background job lifecycle and on-disk state.
//
// It is safe for concurrent use. Writes to meta.json go through the entry's
// mutex. Subscriber fan-out is non-blocking; slow subscribers lose events.
type JobManager struct {
	root      string
	retention time.Duration

	mu      sync.Mutex
	jobs    map[string]*jobEntry
	subs    map[uint64]chan *pb.JobEvent
	nextSub uint64
}

// NewJobManager constructs a manager rooted at dir (created if missing) and
// recovers existing job records from disk. Callers should call Recover before
// accepting new jobs so stale running entries are reconciled.
func NewJobManager(dir string, retention time.Duration) (*JobManager, error) {
	if retention <= 0 {
		retention = defaultRetention
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create jobs dir: %w", err)
	}
	return &JobManager{
		root:      dir,
		retention: retention,
		jobs:      make(map[string]*jobEntry),
		subs:      make(map[uint64]chan *pb.JobEvent),
	}, nil
}

// Recover loads job records from disk and reconciles state. Jobs previously
// marked RUNNING but whose pid is no longer alive are flipped to ORPHANED.
// Expired terminal jobs are garbage-collected.
func (m *JobManager) Recover() {
	entries, err := os.ReadDir(m.root)
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(m.root, e.Name())
		meta, err := loadMeta(dir)
		if err != nil {
			log.Printf("jobs: skip %s: %v", e.Name(), err)
			continue
		}
		// Reconcile running-without-tracker.
		if meta.Status == pb.JobStatus_JOB_STATUS_RUNNING {
			if !pidAlive(meta.Pid) {
				meta.Status = pb.JobStatus_JOB_STATUS_ORPHANED
				meta.EndedAt = now.Format(time.RFC3339Nano)
				meta.Error = "agent restarted while job was running; exit code unknown"
				_ = saveMeta(dir, meta)
			}
		}
		// TTL prune.
		if isTerminal(meta.Status) && meta.EndedAt != "" {
			if t, perr := time.Parse(time.RFC3339Nano, meta.EndedAt); perr == nil {
				if now.Sub(t) > m.retention {
					_ = os.RemoveAll(dir)
					continue
				}
			}
		}
		m.jobs[meta.JobId] = &jobEntry{meta: meta, dir: dir}
	}
}

// Subscribe returns a channel that receives job events, plus a cancel func.
// The channel is closed when the caller calls cancel.
func (m *JobManager) Subscribe() (<-chan *pb.JobEvent, func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextSub
	m.nextSub++
	ch := make(chan *pb.JobEvent, 64)
	m.subs[id] = ch
	return ch, func() {
		m.mu.Lock()
		if existing, ok := m.subs[id]; ok {
			delete(m.subs, id)
			close(existing)
		}
		m.mu.Unlock()
	}
}

// Snapshot returns the current jobs slice newest-first, suitable for a
// WatchJobs replay. It does not hold entry locks during copy.
func (m *JobManager) Snapshot() []*pb.Job {
	m.mu.Lock()
	entries := make([]*jobEntry, 0, len(m.jobs))
	for _, e := range m.jobs {
		entries = append(entries, e)
	}
	m.mu.Unlock()
	out := make([]*pb.Job, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.cloneMeta())
	}
	sortJobsNewestFirst(out)
	return out
}

// broadcast fans an event out to all subscribers. Drops on full channels.
func (m *JobManager) broadcast(ev *pb.JobEvent) {
	m.mu.Lock()
	subs := make([]chan *pb.JobEvent, 0, len(m.subs))
	for _, ch := range m.subs {
		subs = append(subs, ch)
	}
	m.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
			// Slow subscriber; drop.
		}
	}
}

// Start creates a new background job for the given command. It returns the
// initial job meta (status=RUNNING). The caller should not touch cmd after
// this returns; the manager owns it.
func (m *JobManager) Start(command, shell, workingDir string, env map[string]string) (*pb.Job, error) {
	id, err := newJobID()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(m.root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create job dir: %w", err)
	}
	stdoutPath := filepath.Join(dir, "stdout.log")
	stderrPath := filepath.Join(dir, "stderr.log")
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("create stdout.log: %w", err)
	}
	stderr, err := os.Create(stderrPath)
	if err != nil {
		stdout.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("create stderr.log: %w", err)
	}

	effectiveShell := shell
	if effectiveShell == "" {
		effectiveShell = defaultShell()
	}

	cmd := buildCommand(effectiveShell, command)
	if workingDir != "" {
		cmd.Dir = workingDir
	}
	applyEnv(cmd, env)
	setDetached(cmd)
	cmd.Stdin = nil
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("start job: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	meta := &pb.Job{
		JobId:      id,
		Command:    command,
		Shell:      effectiveShell,
		WorkingDir: workingDir,
		Env:        cloneEnv(env),
		Pid:        int32(cmd.Process.Pid),
		Status:     pb.JobStatus_JOB_STATUS_RUNNING,
		StartedAt:  now,
	}
	if err := saveMeta(dir, meta); err != nil {
		// Non-fatal: the child is alive and captured; log and continue.
		log.Printf("jobs: save initial meta %s: %v", id, err)
	}
	entry := &jobEntry{
		meta:       meta,
		dir:        dir,
		proc:       cmd.Process,
		stdoutFile: stdout,
		stderrFile: stderr,
		live:       true,
		done:       make(chan struct{}),
	}

	m.mu.Lock()
	m.jobs[id] = entry
	m.mu.Unlock()

	m.broadcast(&pb.JobEvent{Kind: pb.JobEvent_STARTED, Job: proto(meta)})

	go m.trackerLoop(entry, cmd)

	// Opportunistic prune on job start; cheap and keeps the directory lean.
	go m.pruneExpired()

	return proto(meta), nil
}

// trackerLoop waits for the child to exit and persists the terminal state.
func (m *JobManager) trackerLoop(entry *jobEntry, cmd *exec.Cmd) {
	waitErr := cmd.Wait()
	exitCode := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}
	entry.mu.Lock()
	if entry.stdoutFile != nil {
		entry.stdoutFile.Close()
		entry.stdoutFile = nil
	}
	if entry.stderrFile != nil {
		entry.stderrFile.Close()
		entry.stderrFile = nil
	}
	entry.live = false
	entry.proc = nil
	// Status may have already been flipped to CANCELED by a Cancel() call
	// that signalled the process; preserve that.
	if !isTerminal(entry.meta.Status) {
		entry.meta.Status = pb.JobStatus_JOB_STATUS_EXITED
	}
	entry.meta.ExitCode = int32(exitCode)
	if entry.meta.EndedAt == "" {
		entry.meta.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if waitErr != nil && entry.meta.Error == "" && !errors.As(waitErr, new(*exec.ExitError)) {
		entry.meta.Error = waitErr.Error()
	}
	refreshSizes(entry)
	metaCopy := proto(entry.meta)
	dir := entry.dir
	doneCh := entry.done
	entry.mu.Unlock()
	if err := saveMeta(dir, metaCopy); err != nil {
		log.Printf("jobs: save terminal meta %s: %v", metaCopy.JobId, err)
	}
	if doneCh != nil {
		close(doneCh)
	}
	m.broadcast(&pb.JobEvent{Kind: pb.JobEvent_COMPLETED, Job: metaCopy})
}

// List returns jobs newest-first, optionally filtered by status.
func (m *JobManager) List(filter pb.JobStatus, limit int32) []*pb.Job {
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	m.pruneExpired()
	m.reconcileLive()
	m.mu.Lock()
	entries := make([]*jobEntry, 0, len(m.jobs))
	for _, e := range m.jobs {
		entries = append(entries, e)
	}
	m.mu.Unlock()
	metas := make([]*pb.Job, 0, len(entries))
	for _, e := range entries {
		meta := e.cloneMeta()
		if filter != pb.JobStatus_JOB_STATUS_UNSPECIFIED && meta.Status != filter {
			continue
		}
		metas = append(metas, meta)
	}
	sortJobsNewestFirst(metas)
	if int32(len(metas)) > limit {
		metas = metas[:limit]
	}
	return metas
}

// Get returns a clone of a single job's meta, or ErrJobNotFound.
func (m *JobManager) Get(id string) (*pb.Job, error) {
	m.reconcileOne(id)
	m.mu.Lock()
	e, ok := m.jobs[id]
	m.mu.Unlock()
	if !ok {
		return nil, ErrJobNotFound
	}
	return e.cloneMeta(), nil
}

// ErrJobNotFound is returned when a job ID does not match any tracked job.
var ErrJobNotFound = errors.New("job not found")

// GetOutput returns captured output for a job. `tailLines>0` returns only the
// last N lines; `maxBytes` caps the response (0 = default 1 MiB, clamped to
// 8 MiB).
func (m *JobManager) GetOutput(id string, streamSel pb.GetJobOutputRequest_Stream, tailLines int32, maxBytes int64) (*pb.GetJobOutputResponse, error) {
	m.mu.Lock()
	e, ok := m.jobs[id]
	m.mu.Unlock()
	if !ok {
		return nil, ErrJobNotFound
	}
	e.mu.Lock()
	dir := e.dir
	e.mu.Unlock()
	if maxBytes <= 0 {
		maxBytes = defaultOutputBytes
	}
	if maxBytes > maxOutputBytes {
		maxBytes = maxOutputBytes
	}
	resp := &pb.GetJobOutputResponse{}
	if streamSel == pb.GetJobOutputRequest_BOTH || streamSel == pb.GetJobOutputRequest_STDOUT {
		data, total, truncated, err := readTail(filepath.Join(dir, "stdout.log"), tailLines, maxBytes)
		if err != nil {
			return nil, err
		}
		resp.Stdout = data
		resp.StdoutTotalBytes = total
		resp.Truncated = resp.Truncated || truncated
	} else {
		_, total, _, _ := readTail(filepath.Join(dir, "stdout.log"), 0, 0)
		resp.StdoutTotalBytes = total
	}
	if streamSel == pb.GetJobOutputRequest_BOTH || streamSel == pb.GetJobOutputRequest_STDERR {
		data, total, truncated, err := readTail(filepath.Join(dir, "stderr.log"), tailLines, maxBytes)
		if err != nil {
			return nil, err
		}
		resp.Stderr = data
		resp.StderrTotalBytes = total
		resp.Truncated = resp.Truncated || truncated
	} else {
		_, total, _, _ := readTail(filepath.Join(dir, "stderr.log"), 0, 0)
		resp.StderrTotalBytes = total
	}
	return resp, nil
}

// Cancel requests termination of a running job. force=true uses SIGKILL /
// taskkill /F. For already-terminal jobs the current meta is returned
// unchanged. Cancel blocks until the tracker goroutine has reaped the
// process and released its file handles, so a subsequent Delete or
// GetOutput sees a consistent filesystem state.
func (m *JobManager) Cancel(id string, force bool) (*pb.Job, error) {
	m.mu.Lock()
	e, ok := m.jobs[id]
	m.mu.Unlock()
	if !ok {
		return nil, ErrJobNotFound
	}
	e.mu.Lock()
	if isTerminal(e.meta.Status) {
		snap := proto(e.meta)
		e.mu.Unlock()
		return snap, nil
	}
	pid := e.meta.Pid
	// Mark the intent BEFORE signalling so the tracker's exit path sees
	// CANCELED instead of overwriting with EXITED. Also set EndedAt so a
	// post-cancel read before the tracker completes sees a consistent meta.
	e.meta.Status = pb.JobStatus_JOB_STATUS_CANCELED
	e.meta.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	snap := proto(e.meta)
	dir := e.dir
	doneCh := e.done
	live := e.live
	e.mu.Unlock()
	_ = saveMeta(dir, snap)
	if err := killProcessTree(pid, force); err != nil {
		log.Printf("jobs: kill pid %d for job %s: %v", pid, id, err)
	}
	m.broadcast(&pb.JobEvent{Kind: pb.JobEvent_UPDATED, Job: snap})
	// Wait for tracker to reap the process so file handles are released
	// before we return (important on Windows where held handles block
	// subsequent Delete / os.Remove calls).
	if live && doneCh != nil {
		select {
		case <-doneCh:
		case <-time.After(5 * time.Second):
			log.Printf("jobs: tracker for %s did not complete within 5s after cancel", id)
		}
	}
	// Re-fetch the freshly-saved terminal meta so callers see final size
	// counters and preserved EndedAt.
	e.mu.Lock()
	final := proto(e.meta)
	e.mu.Unlock()
	return final, nil
}

// Delete removes a terminal job's directory. Returns ErrJobNotFound if the
// job is unknown, or an error if the job is still running.
func (m *JobManager) Delete(id string) (bool, error) {
	m.mu.Lock()
	e, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return false, ErrJobNotFound
	}
	e.mu.Lock()
	if !isTerminal(e.meta.Status) {
		e.mu.Unlock()
		m.mu.Unlock()
		return false, errors.New("cannot delete a running job; cancel first")
	}
	dir := e.dir
	e.mu.Unlock()
	delete(m.jobs, id)
	m.mu.Unlock()
	if err := os.RemoveAll(dir); err != nil {
		return false, err
	}
	m.broadcast(&pb.JobEvent{Kind: pb.JobEvent_DELETED, JobId: id})
	return true, nil
}

// reconcileLive walks tracked RUNNING jobs that have no live tracker and
// flips them to ORPHANED if the PID is gone. Runs under the manager lock.
func (m *JobManager) reconcileLive() {
	m.mu.Lock()
	entries := make([]*jobEntry, 0, len(m.jobs))
	for _, e := range m.jobs {
		entries = append(entries, e)
	}
	m.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, e := range entries {
		e.mu.Lock()
		if e.meta.Status == pb.JobStatus_JOB_STATUS_RUNNING && !e.live {
			if !pidAlive(e.meta.Pid) {
				e.meta.Status = pb.JobStatus_JOB_STATUS_ORPHANED
				e.meta.EndedAt = now
				if e.meta.Error == "" {
					e.meta.Error = "agent restarted while job was running; exit code unknown"
				}
				snap := proto(e.meta)
				dir := e.dir
				e.mu.Unlock()
				_ = saveMeta(dir, snap)
				m.broadcast(&pb.JobEvent{Kind: pb.JobEvent_COMPLETED, Job: snap})
				continue
			}
		}
		e.mu.Unlock()
	}
}

func (m *JobManager) reconcileOne(id string) {
	m.mu.Lock()
	e, ok := m.jobs[id]
	m.mu.Unlock()
	if !ok {
		return
	}
	e.mu.Lock()
	if e.meta.Status == pb.JobStatus_JOB_STATUS_RUNNING && !e.live && !pidAlive(e.meta.Pid) {
		e.meta.Status = pb.JobStatus_JOB_STATUS_ORPHANED
		e.meta.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if e.meta.Error == "" {
			e.meta.Error = "agent restarted while job was running; exit code unknown"
		}
		snap := proto(e.meta)
		dir := e.dir
		e.mu.Unlock()
		_ = saveMeta(dir, snap)
		m.broadcast(&pb.JobEvent{Kind: pb.JobEvent_COMPLETED, Job: snap})
		return
	}
	e.mu.Unlock()
}

// pruneExpired removes terminal jobs whose ended_at is older than retention.
func (m *JobManager) pruneExpired() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.jobs))
	for id, e := range m.jobs {
		e.mu.Lock()
		if isTerminal(e.meta.Status) && e.meta.EndedAt != "" {
			if t, err := time.Parse(time.RFC3339Nano, e.meta.EndedAt); err == nil {
				if time.Since(t) > m.retention {
					ids = append(ids, id)
				}
			}
		}
		e.mu.Unlock()
	}
	dirs := make([]string, 0, len(ids))
	for _, id := range ids {
		if e, ok := m.jobs[id]; ok {
			dirs = append(dirs, e.dir)
			delete(m.jobs, id)
		}
	}
	m.mu.Unlock()
	for i, d := range dirs {
		_ = os.RemoveAll(d)
		m.broadcast(&pb.JobEvent{Kind: pb.JobEvent_DELETED, JobId: ids[i]})
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (e *jobEntry) cloneMeta() *pb.Job {
	e.mu.Lock()
	defer e.mu.Unlock()
	refreshSizes(e)
	return proto(e.meta)
}

// refreshSizes updates StdoutBytes/StderrBytes from the filesystem. Must be
// called with e.mu held.
func refreshSizes(e *jobEntry) {
	if st, err := os.Stat(filepath.Join(e.dir, "stdout.log")); err == nil {
		e.meta.StdoutBytes = st.Size()
	}
	if st, err := os.Stat(filepath.Join(e.dir, "stderr.log")); err == nil {
		e.meta.StderrBytes = st.Size()
	}
}

// proto returns a deep copy of a Job message.
func proto(m *pb.Job) *pb.Job {
	if m == nil {
		return nil
	}
	out := &pb.Job{
		JobId:       m.JobId,
		Command:     m.Command,
		Shell:       m.Shell,
		WorkingDir:  m.WorkingDir,
		Pid:         m.Pid,
		Status:      m.Status,
		ExitCode:    m.ExitCode,
		StartedAt:   m.StartedAt,
		EndedAt:     m.EndedAt,
		StdoutBytes: m.StdoutBytes,
		StderrBytes: m.StderrBytes,
		Error:       m.Error,
	}
	if len(m.Env) > 0 {
		out.Env = make(map[string]string, len(m.Env))
		for k, v := range m.Env {
			out.Env[k] = v
		}
	}
	return out
}

func cloneEnv(env map[string]string) map[string]string {
	if len(env) == 0 {
		return nil
	}
	out := make(map[string]string, len(env))
	for k, v := range env {
		out[k] = v
	}
	return out
}

func isTerminal(s pb.JobStatus) bool {
	switch s {
	case pb.JobStatus_JOB_STATUS_EXITED,
		pb.JobStatus_JOB_STATUS_CANCELED,
		pb.JobStatus_JOB_STATUS_ORPHANED:
		return true
	}
	return false
}

// sortJobsNewestFirst sorts by started_at descending.
func sortJobsNewestFirst(js []*pb.Job) {
	sort.SliceStable(js, func(i, j int) bool {
		return js[i].StartedAt > js[j].StartedAt
	})
}

// newJobID returns a sortable, path-safe job id.
// Format: 20060102T150405Z-<6 hex>
func newJobID() (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s",
		time.Now().UTC().Format("20060102T150405Z"),
		hex.EncodeToString(b[:])), nil
}

// isValidJobID validates a job id before touching the filesystem. Paranoia
// against path-traversal via crafted ids.
func isValidJobID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// loadMeta reads and parses meta.json from a job directory.
func loadMeta(dir string) (*pb.Job, error) {
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}
	m := &pb.Job{}
	if err := protojson.Unmarshal(data, m); err != nil {
		// Tolerate legacy or corrupt files: fall back to best-effort decode.
		var generic map[string]any
		if jerr := json.Unmarshal(data, &generic); jerr != nil {
			return nil, fmt.Errorf("parse meta.json: %w", err)
		}
		return nil, fmt.Errorf("parse meta.json: %w", err)
	}
	if !isValidJobID(m.JobId) {
		return nil, fmt.Errorf("invalid job id in meta.json: %q", m.JobId)
	}
	return m, nil
}

// saveMeta writes meta.json atomically (tmp + rename).
func saveMeta(dir string, m *pb.Job) error {
	data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(m)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "meta.json.tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "meta.json"))
}

// readTail reads up to maxBytes from the file, optionally limited to the last
// tailLines lines. Returns (data, totalBytes, truncated, err).
// If maxBytes == 0 the file size is used but nothing is read (totals only).
func readTail(path string, tailLines int32, maxBytes int64) ([]byte, int64, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, false, nil
		}
		return nil, 0, false, err
	}
	total := info.Size()
	if maxBytes == 0 {
		return nil, total, false, nil
	}

	readSize := total
	truncated := false
	if readSize > maxBytes {
		readSize = maxBytes
		truncated = true
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, total, false, err
	}
	defer f.Close()
	if truncated {
		if _, err := f.Seek(-readSize, io.SeekEnd); err != nil {
			return nil, total, false, err
		}
	}
	buf := make([]byte, readSize)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, total, truncated, err
	}
	buf = buf[:n]
	if tailLines > 0 {
		buf = lastLines(buf, int(tailLines))
	}
	return buf, total, truncated, nil
}

// lastLines returns the last n lines of buf. When buf was already truncated
// at a non-line boundary the leading partial line is dropped.
func lastLines(buf []byte, n int) []byte {
	if n <= 0 || len(buf) == 0 {
		return buf
	}
	count := 0
	i := len(buf) - 1
	// Ignore a single trailing newline.
	if buf[i] == '\n' {
		i--
	}
	for ; i >= 0; i-- {
		if buf[i] == '\n' {
			count++
			if count == n {
				return buf[i+1:]
			}
		}
	}
	return buf
}

// -----------------------------------------------------------------------------
// Executor integration
// -----------------------------------------------------------------------------

// globalJobManager is the process-wide job manager, initialised in main.
var globalJobManager atomic.Pointer[JobManager]

func setJobManager(m *JobManager) { globalJobManager.Store(m) }
func getJobManager() *JobManager  { return globalJobManager.Load() }

// startDetachedJob is used by the executor's detach branch. Returns the
// initial job snapshot or an error.
func startDetachedJob(command, shell, workingDir string, env map[string]string) (*pb.Job, error) {
	m := getJobManager()
	if m == nil {
		return nil, errors.New("job manager not initialised")
	}
	return m.Start(command, shell, workingDir, env)
}


