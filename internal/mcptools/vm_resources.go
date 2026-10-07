package mcptools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/registry"
)

func checkWindowsVMResources(
	ctx context.Context,
	plan windowsVMPlan,
	reg *registry.Registry,
	pool *agentclient.Pool,
) (map[string]any, error) {
	target, err := resolvePlanTarget(plan.Target, reg)
	if err != nil {
		return nil, err
	}
	script, err := hyperv.BuildResourceSafetyScript(hyperv.ResourceSafetyParams{
		MemoryMB:                  plan.MemoryMB,
		StoragePath:               plan.VHDPath,
		ReserveVHDPath:            plan.BaseVHD,
		ReserveRemainingGrowth:    false,
		MinHostReservePct:         plan.MinHostReservePct,
		AllowHostResourcePressure: plan.AllowHostResourcePressure,
	})
	if err != nil {
		return nil, err
	}
	out, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return nil, err
	}
	var safety map[string]any
	if err := json.Unmarshal([]byte(jsonExtract(out)), &safety); err != nil {
		return nil, fmt.Errorf("parse VM resource safety result: %w", err)
	}
	return safety, nil
}
