package main

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/nijosmsft/lablink/proto/agent"

	"github.com/shirou/gopsutil/v4/process"
)

func listProcesses(ctx context.Context, nameFilter string) (*pb.ListProcessesResponse, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}

	var result []*pb.ProcessInfo
	for _, p := range procs {
		name, _ := p.NameWithContext(ctx)
		if nameFilter != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(nameFilter)) {
			continue
		}

		cmdLine, _ := p.CmdlineWithContext(ctx)
		memInfo, _ := p.MemoryInfoWithContext(ctx)
		cpuPct, _ := p.CPUPercentWithContext(ctx)

		var memBytes int64
		if memInfo != nil {
			memBytes = int64(memInfo.RSS)
		}

		result = append(result, &pb.ProcessInfo{
			Pid:         int32(p.Pid),
			Name:        name,
			CommandLine: cmdLine,
			MemoryBytes: memBytes,
			CpuPercent:  cpuPct,
		})
	}

	return &pb.ListProcessesResponse{Processes: result}, nil
}

func killProcess(_ context.Context, pid int32, force bool) (*pb.KillProcessResponse, error) {
	p, err := process.NewProcess(pid)
	if err != nil {
		return &pb.KillProcessResponse{
			Success: false,
			Message: fmt.Sprintf("process %d not found: %v", pid, err),
		}, nil
	}

	if force {
		err = p.Kill()
	} else {
		err = p.Terminate()
	}

	if err != nil {
		return &pb.KillProcessResponse{
			Success: false,
			Message: fmt.Sprintf("failed to kill process %d: %v", pid, err),
		}, nil
	}

	return &pb.KillProcessResponse{
		Success: true,
		Message: fmt.Sprintf("process %d killed", pid),
	}, nil
}
