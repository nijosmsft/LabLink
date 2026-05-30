package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

// jobJSON is the JSON shape delivered to the browser. Mirrors pb.Job but
// uses plain JSON names and explodes the status enum into a label.
type jobJSON struct {
	JobID       string `json:"job_id"`
	Node        string `json:"node"`
	Command     string `json:"command"`
	Shell       string `json:"shell"`
	WorkingDir  string `json:"working_dir,omitempty"`
	Pid         int32  `json:"pid"`
	Status      string `json:"status"`
	ExitCode    int32  `json:"exit_code"`
	StartedAt   string `json:"started_at"`
	EndedAt     string `json:"ended_at,omitempty"`
	StdoutBytes int64  `json:"stdout_bytes"`
	StderrBytes int64  `json:"stderr_bytes"`
	Error       string `json:"error,omitempty"`
}

func statusText(s pb.JobStatus) string {
	switch s {
	case pb.JobStatus_JOB_STATUS_RUNNING:
		return "running"
	case pb.JobStatus_JOB_STATUS_EXITED:
		return "exited"
	case pb.JobStatus_JOB_STATUS_CANCELED:
		return "canceled"
	case pb.JobStatus_JOB_STATUS_ORPHANED:
		return "orphaned"
	}
	return "unknown"
}

func parsePortalStatus(s string) pb.JobStatus {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "running":
		return pb.JobStatus_JOB_STATUS_RUNNING
	case "exited", "finished", "done":
		return pb.JobStatus_JOB_STATUS_EXITED
	case "canceled", "cancelled":
		return pb.JobStatus_JOB_STATUS_CANCELED
	case "orphaned":
		return pb.JobStatus_JOB_STATUS_ORPHANED
	}
	return pb.JobStatus_JOB_STATUS_UNSPECIFIED
}

func parsePortalStream(s string) pb.GetJobOutputRequest_Stream {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "stdout":
		return pb.GetJobOutputRequest_STDOUT
	case "stderr":
		return pb.GetJobOutputRequest_STDERR
	}
	return pb.GetJobOutputRequest_BOTH
}

func toJobJSON(nodeName string, j *pb.Job) jobJSON {
	if j == nil {
		return jobJSON{Node: nodeName}
	}
	return jobJSON{
		JobID:       j.JobId,
		Node:        nodeName,
		Command:     j.Command,
		Shell:       j.Shell,
		WorkingDir:  j.WorkingDir,
		Pid:         j.Pid,
		Status:      statusText(j.Status),
		ExitCode:    j.ExitCode,
		StartedAt:   j.StartedAt,
		EndedAt:     j.EndedAt,
		StdoutBytes: j.StdoutBytes,
		StderrBytes: j.StderrBytes,
		Error:       j.Error,
	}
}

// targetNodes resolves the ?node= query param to a slice of nodes. If empty,
// returns all registered nodes.
func (s *Server) targetNodes(nodeName string) []*registry.Node {
	if nodeName == "" {
		return s.reg.AllNodes()
	}
	n, ok := s.reg.GetNode(nodeName)
	if !ok {
		return nil
	}
	return []*registry.Node{n}
}

// shortNodeCtx creates a context with an upper bound so a single hung node
// can't block the whole handler.
func shortNodeCtx(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = 10 * time.Second
	}
	return context.WithTimeout(parent, d)
}

func (s *Server) handleJobsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.reg == nil || s.pool == nil {
		http.Error(w, "jobs API not configured", http.StatusServiceUnavailable)
		return
	}
	statusFilter := parsePortalStatus(r.URL.Query().Get("status"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	nodes := s.targetNodes(r.URL.Query().Get("node"))

	type nodeErr struct {
		Node  string `json:"node"`
		Error string `json:"error"`
	}
	var (
		mu     sync.Mutex
		jobs   []jobJSON
		errs   []nodeErr
		wg     sync.WaitGroup
	)
	for _, n := range nodes {
		wg.Add(1)
		go func(node *registry.Node) {
			defer wg.Done()
			client, err := s.pool.GetClient(node.Address, node.TLSServerName)
			if err != nil {
				mu.Lock()
				errs = append(errs, nodeErr{Node: node.Name, Error: err.Error()})
				mu.Unlock()
				return
			}
			ctx, cancel := shortNodeCtx(r.Context(), 10*time.Second)
			defer cancel()
			resp, err := client.ListJobs(ctx, &pb.ListJobsRequest{
				StatusFilter: statusFilter,
				Limit:        int32(limit),
			})
			if err != nil {
				mu.Lock()
				errs = append(errs, nodeErr{Node: node.Name, Error: err.Error()})
				mu.Unlock()
				return
			}
			mu.Lock()
			for _, j := range resp.Jobs {
				jobs = append(jobs, toJobJSON(node.Name, j))
			}
			mu.Unlock()
		}(n)
	}
	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jobs":   jobs,
		"errors": errs,
	})
}

func (s *Server) resolveJobNode(r *http.Request) (*registry.Node, string, bool, error) {
	nodeName := r.URL.Query().Get("node")
	jobID := r.URL.Query().Get("id")
	if nodeName == "" || jobID == "" {
		return nil, "", false, fmt.Errorf("node and id are required")
	}
	n, ok := s.reg.GetNode(nodeName)
	if !ok {
		return nil, jobID, false, fmt.Errorf("unknown node %q", nodeName)
	}
	return n, jobID, true, nil
}

func (s *Server) handleJobGet(w http.ResponseWriter, r *http.Request) {
	if s.reg == nil || s.pool == nil {
		http.Error(w, "jobs API not configured", http.StatusServiceUnavailable)
		return
	}
	node, jobID, ok, err := s.resolveJobNode(r)
	if !ok {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	client, err := s.pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ctx, cancel := shortNodeCtx(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := client.GetJob(ctx, &pb.GetJobRequest{JobId: jobID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toJobJSON(node.Name, resp.Job))
}

func (s *Server) handleJobOutput(w http.ResponseWriter, r *http.Request) {
	if s.reg == nil || s.pool == nil {
		http.Error(w, "jobs API not configured", http.StatusServiceUnavailable)
		return
	}
	node, jobID, ok, err := s.resolveJobNode(r)
	if !ok {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tailLines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	maxBytes, _ := strconv.ParseInt(r.URL.Query().Get("max_bytes"), 10, 64)
	streamSel := parsePortalStream(r.URL.Query().Get("stream"))

	client, err := s.pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ctx, cancel := shortNodeCtx(r.Context(), 15*time.Second)
	defer cancel()
	resp, err := client.GetJobOutput(ctx, &pb.GetJobOutputRequest{
		JobId:     jobID,
		Stream:    streamSel,
		TailLines: int32(tailLines),
		MaxBytes:  maxBytes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"stdout":             string(resp.Stdout),
		"stderr":             string(resp.Stderr),
		"stdout_total_bytes": resp.StdoutTotalBytes,
		"stderr_total_bytes": resp.StderrTotalBytes,
		"truncated":          resp.Truncated,
	})
}

func (s *Server) handleJobCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.reg == nil || s.pool == nil {
		http.Error(w, "jobs API not configured", http.StatusServiceUnavailable)
		return
	}
	node, jobID, ok, err := s.resolveJobNode(r)
	if !ok {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	force := strings.EqualFold(r.URL.Query().Get("force"), "true")
	client, err := s.pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ctx, cancel := shortNodeCtx(r.Context(), 15*time.Second)
	defer cancel()
	resp, err := client.CancelJob(ctx, &pb.CancelJobRequest{JobId: jobID, Force: force})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toJobJSON(node.Name, resp.Job))
}

func (s *Server) handleJobDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.reg == nil || s.pool == nil {
		http.Error(w, "jobs API not configured", http.StatusServiceUnavailable)
		return
	}
	node, jobID, ok, err := s.resolveJobNode(r)
	if !ok {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	client, err := s.pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ctx, cancel := shortNodeCtx(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := client.DeleteJob(ctx, &pb.DeleteJobRequest{JobId: jobID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"deleted": resp.Deleted})
}

// handleJobsStream is the SSE endpoint that fans out WatchJobs streams from
// every registered node onto a single text/event-stream connection.
//
// Events written to the browser:
//
//	{"kind":"snapshot","node":"n","job":{...}}    — replayed on connect
//	{"kind":"started"|"updated"|"completed","node":"n","job":{...}}
//	{"kind":"deleted","node":"n","job_id":"..."}
//	{"kind":"node_error","node":"n","error":"..."} — unreachable node
//
// Each registered node gets one WatchJobs goroutine. Node membership is
// snapshotted at connect time; nodes added later won't be streamed until the
// browser reconnects. This keeps the implementation small and is fine for a
// local UI where reload is cheap.
func (s *Server) handleJobsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	if s.reg == nil || s.pool == nil {
		http.Error(w, "jobs API not configured", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	eventCh := make(chan []byte, 256)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	nodes := s.reg.AllNodes()
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(node *registry.Node) {
			defer wg.Done()
			s.watchNodeJobs(ctx, node, eventCh)
		}(n)
	}

	// Close eventCh only after all watchers return.
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			// Drain remaining watchers so goroutines exit cleanly.
			go func() {
				for range eventCh {
				}
			}()
			<-doneCh
			return
		case b := <-eventCh:
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-doneCh:
			// All watchers exited (e.g. no nodes registered). Keep the
			// connection open with pings so the browser doesn't thrash
			// reconnects; a page reload will re-snapshot.
			doneCh = nil
		}
	}
}

func (s *Server) watchNodeJobs(ctx context.Context, node *registry.Node, out chan<- []byte) {
	send := func(kind string, payload map[string]any) {
		if payload == nil {
			payload = map[string]any{}
		}
		payload["kind"] = kind
		payload["node"] = node.Name
		b, err := json.Marshal(payload)
		if err != nil {
			return
		}
		select {
		case out <- b:
		case <-ctx.Done():
		}
	}

	client, err := s.pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		send("node_error", map[string]any{"error": err.Error()})
		return
	}
	stream, err := client.WatchJobs(ctx, &pb.WatchJobsRequest{})
	if err != nil {
		send("node_error", map[string]any{"error": err.Error()})
		return
	}

	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			return
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			send("node_error", map[string]any{"error": err.Error()})
			return
		}
		kind := watchEventKind(ev.Kind)
		if kind == "deleted" {
			send(kind, map[string]any{"job_id": ev.JobId})
			continue
		}
		if ev.Job == nil {
			continue
		}
		send(kind, map[string]any{"job": toJobJSON(node.Name, ev.Job)})
	}
}

func watchEventKind(k pb.JobEvent_Kind) string {
	switch k {
	case pb.JobEvent_SNAPSHOT:
		return "snapshot"
	case pb.JobEvent_STARTED:
		return "started"
	case pb.JobEvent_UPDATED:
		return "updated"
	case pb.JobEvent_COMPLETED:
		return "completed"
	case pb.JobEvent_DELETED:
		return "deleted"
	}
	return "updated"
}

// registerJobsHandlers attaches the /api/jobs endpoints to the portal mux.
// Called from New when reg + pool are provided.
func (s *Server) registerJobsHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api/jobs", s.handleJobsList)
	mux.HandleFunc("/api/jobs/get", s.handleJobGet)
	mux.HandleFunc("/api/jobs/output", s.handleJobOutput)
	mux.HandleFunc("/api/jobs/cancel", s.handleJobCancel)
	mux.HandleFunc("/api/jobs/delete", s.handleJobDelete)
	mux.HandleFunc("/api/jobs/stream", s.handleJobsStream)
}

// Compile-time assertion that agentclient.Pool satisfies our local interface;
// we don't actually use an interface (Pool is the concrete type), but keep the
// import referenced so small test builds don't drop it.
var _ = (*agentclient.Pool)(nil)
