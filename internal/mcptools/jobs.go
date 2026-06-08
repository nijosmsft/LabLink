package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

// RegisterJobs exposes the background-job tools (detached executions).
func RegisterJobs(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, leaseCfg LeaseGateConfig) {
	s.AddTool(
		mcp.NewTool("list_jobs",
			mcp.WithDescription("List background jobs (detached executions) on a node. Newest first."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("status", mcp.Description("Filter by status: running, exited, canceled, orphaned, all (default)")),
			mcp.WithNumber("limit", mcp.Description("Max rows to return (default 50, max 500)")),
		),
		listJobsHandler(reg, pool),
	)

	s.AddTool(
		mcp.NewTool("get_job_status",
			mcp.WithDescription("Get metadata for a single background job: status, pid, exit code, timing, output sizes."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("job_id", mcp.Required(), mcp.Description("Job identifier returned by execute_command / schedule_command")),
		),
		getJobStatusHandler(reg, pool),
	)

	s.AddTool(
		mcp.NewTool("get_job_output",
			mcp.WithDescription("Fetch captured stdout/stderr of a background job. Defaults to the last 200 lines, capped at 1 MiB."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("job_id", mcp.Required(), mcp.Description("Job identifier")),
			mcp.WithString("stream", mcp.Description("Which stream to fetch: stdout, stderr, both (default)")),
			mcp.WithNumber("tail_lines", mcp.Description("Return only the last N lines (default 200; 0 = whole file subject to max_bytes)")),
			mcp.WithNumber("max_bytes", mcp.Description("Hard cap on bytes per stream (default 1048576, max 8388608)")),
		),
		getJobOutputHandler(reg, pool),
	)

	s.AddTool(
		mcp.NewTool("cancel_job",
			mcp.WithDescription("Cancel a running background job. Terminates the process tree."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("job_id", mcp.Required(), mcp.Description("Job identifier")),
			mcp.WithBoolean("force", mcp.Description("Force-terminate (taskkill /F on Windows, SIGKILL on Unix)")),
		),
		LeaseGate(leaseCfg, extractJobNode(), cancelJobHandler(reg, pool)),
	)

	s.AddTool(
		mcp.NewTool("delete_job",
			mcp.WithDescription("Delete a terminal background job's records (meta + captured output) from the node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("job_id", mcp.Required(), mcp.Description("Job identifier")),
		),
		LeaseGate(leaseCfg, extractJobNode(), deleteJobHandler(reg, pool)),
	)
}

func parseStatusFilter(s string) pb.JobStatus {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "all", "any":
		return pb.JobStatus_JOB_STATUS_UNSPECIFIED
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

func parseStreamSelector(s string) pb.GetJobOutputRequest_Stream {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "stdout":
		return pb.GetJobOutputRequest_STDOUT
	case "stderr":
		return pb.GetJobOutputRequest_STDERR
	}
	return pb.GetJobOutputRequest_BOTH
}

func statusLabel(s pb.JobStatus) string {
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

func listJobsHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		statusStr := request.GetString("status", "")
		limit := int32(request.GetInt("limit", 0))

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		ctx, op := beginOp(ctx, "list_jobs", nodeName, "", map[string]string{
			"status": statusStr,
			"limit":  fmt.Sprintf("%d", limit),
		})
		var opErr error
		defer func() { op.Done(opErr) }()

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}
		callCtx, callCancel := nodeCallContext(ctx, nodeName)
		defer callCancel()
		resp, err := client.ListJobs(callCtx, &pb.ListJobsRequest{
			StatusFilter: parseStatusFilter(statusStr),
			Limit:        limit,
		})
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("list_jobs: %v", err)), nil
		}

		if len(resp.Jobs) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No jobs on %s.", nodeName)), nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Jobs on %s (%d):\n\n", nodeName, len(resp.Jobs))
		for _, j := range resp.Jobs {
			renderJobLine(&b, j)
		}
		return mcp.NewToolResultText(b.String()), nil
	}
}

func renderJobLine(b *strings.Builder, j *pb.Job) {
	cmd := j.Command
	if len(cmd) > 80 {
		cmd = cmd[:77] + "..."
	}
	cmd = strings.ReplaceAll(cmd, "\n", " ")
	status := statusLabel(j.Status)
	if j.Status == pb.JobStatus_JOB_STATUS_EXITED {
		status = fmt.Sprintf("exited(%d)", j.ExitCode)
	}
	fmt.Fprintf(b, "  %s  %-12s  pid=%-6d  started=%s\n",
		j.JobId, status, j.Pid, j.StartedAt)
	fmt.Fprintf(b, "    cmd: %s\n", cmd)
}

func getJobStatusHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		jobID := request.GetString("job_id", "")
		if jobID == "" {
			return mcp.NewToolResultError("job_id is required"), nil
		}
		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}
		ctx, op := beginOp(ctx, "get_job_status", nodeName, jobID, nil)
		var opErr error
		defer func() { op.Done(opErr) }()

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}
		callCtx, callCancel := nodeCallContext(ctx, nodeName)
		defer callCancel()
		resp, err := client.GetJob(callCtx, &pb.GetJobRequest{JobId: jobID})
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("get_job: %v", err)), nil
		}
		j := resp.Job
		var b strings.Builder
		fmt.Fprintf(&b, "Job %s on %s\n", j.JobId, nodeName)
		fmt.Fprintf(&b, "  status:     %s\n", statusLabel(j.Status))
		fmt.Fprintf(&b, "  pid:        %d\n", j.Pid)
		fmt.Fprintf(&b, "  started:    %s\n", j.StartedAt)
		if j.EndedAt != "" {
			fmt.Fprintf(&b, "  ended:      %s\n", j.EndedAt)
		}
		if j.Status == pb.JobStatus_JOB_STATUS_EXITED || j.Status == pb.JobStatus_JOB_STATUS_CANCELED {
			fmt.Fprintf(&b, "  exit_code:  %d\n", j.ExitCode)
		}
		fmt.Fprintf(&b, "  shell:      %s\n", j.Shell)
		if j.WorkingDir != "" {
			fmt.Fprintf(&b, "  working:    %s\n", j.WorkingDir)
		}
		fmt.Fprintf(&b, "  stdout:     %d bytes\n", j.StdoutBytes)
		fmt.Fprintf(&b, "  stderr:     %d bytes\n", j.StderrBytes)
		if j.Error != "" {
			fmt.Fprintf(&b, "  error:      %s\n", j.Error)
		}
		fmt.Fprintf(&b, "  command:\n    %s\n", strings.ReplaceAll(j.Command, "\n", "\n    "))
		return mcp.NewToolResultText(b.String()), nil
	}
}

func getJobOutputHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		jobID := request.GetString("job_id", "")
		streamStr := request.GetString("stream", "")
		tailLines := int32(request.GetInt("tail_lines", 200))
		maxBytes := int64(request.GetInt("max_bytes", 0))

		if jobID == "" {
			return mcp.NewToolResultError("job_id is required"), nil
		}
		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		ctx, op := beginOp(ctx, "get_job_output", nodeName, jobID, map[string]string{
			"stream":     streamStr,
			"tail_lines": fmt.Sprintf("%d", tailLines),
		})
		var opErr error
		defer func() { op.Done(opErr) }()

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}
		callCtx, callCancel := nodeCallContext(ctx, nodeName)
		defer callCancel()
		resp, err := client.GetJobOutput(callCtx, &pb.GetJobOutputRequest{
			JobId:     jobID,
			Stream:    parseStreamSelector(streamStr),
			TailLines: tailLines,
			MaxBytes:  maxBytes,
		})
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("get_job_output: %v", err)), nil
		}

		var b strings.Builder
		fmt.Fprintf(&b, "Job %s output on %s", jobID, nodeName)
		if resp.Truncated {
			b.WriteString(" (truncated)")
		}
		b.WriteString("\n")
		if len(resp.Stdout) > 0 {
			fmt.Fprintf(&b, "\n--- stdout (%d/%d bytes shown) ---\n", len(resp.Stdout), resp.StdoutTotalBytes)
			b.Write(resp.Stdout)
			if !strings.HasSuffix(string(resp.Stdout), "\n") {
				b.WriteString("\n")
			}
		}
		if len(resp.Stderr) > 0 {
			fmt.Fprintf(&b, "\n--- stderr (%d/%d bytes shown) ---\n", len(resp.Stderr), resp.StderrTotalBytes)
			b.Write(resp.Stderr)
			if !strings.HasSuffix(string(resp.Stderr), "\n") {
				b.WriteString("\n")
			}
		}
		if len(resp.Stdout) == 0 && len(resp.Stderr) == 0 {
			b.WriteString("\n(no output)\n")
		}
		return mcp.NewToolResultText(b.String()), nil
	}
}

func cancelJobHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		jobID := request.GetString("job_id", "")
		force := request.GetBool("force", false)
		if jobID == "" {
			return mcp.NewToolResultError("job_id is required"), nil
		}
		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}
		ctx, op := beginOp(ctx, "cancel_job", nodeName, jobID, map[string]string{"force": fmt.Sprintf("%t", force)})
		var opErr error
		defer func() { op.Done(opErr) }()

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}
		callCtx, callCancel := nodeCallContext(ctx, nodeName)
		defer callCancel()
		resp, err := client.CancelJob(callCtx, &pb.CancelJobRequest{JobId: jobID, Force: force})
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("cancel_job: %v", err)), nil
		}
		j := resp.Job
		return mcp.NewToolResultText(fmt.Sprintf(
			"Job %s on %s: status=%s exit_code=%d ended=%s",
			j.JobId, nodeName, statusLabel(j.Status), j.ExitCode, j.EndedAt)), nil
	}
}

func deleteJobHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		jobID := request.GetString("job_id", "")
		if jobID == "" {
			return mcp.NewToolResultError("job_id is required"), nil
		}
		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}
		ctx, op := beginOp(ctx, "delete_job", nodeName, jobID, nil)
		var opErr error
		defer func() { op.Done(opErr) }()

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}
		callCtx, callCancel := nodeCallContext(ctx, nodeName)
		defer callCancel()
		resp, err := client.DeleteJob(callCtx, &pb.DeleteJobRequest{JobId: jobID})
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("delete_job: %v", err)), nil
		}
		if !resp.Deleted {
			return mcp.NewToolResultText(fmt.Sprintf("Job %s on %s: not deleted", jobID, nodeName)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Job %s on %s deleted.", jobID, nodeName)), nil
	}
}
