package isolatedstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrOrchestratorNotFound = errors.New("isolatedstate: orchestrator not found")
	ErrNetworkNotFound      = errors.New("isolatedstate: private network not found")
	ErrVMNotFound           = errors.New("isolatedstate: isolated VM not found")
	ErrRelayNotFound        = errors.New("isolatedstate: relay not found")
	ErrApprovalNotFound     = errors.New("isolatedstate: approval plan not found")
)

func nowUnix(value UnixSeconds) UnixSeconds {
	if value == 0 {
		return UnixSeconds(time.Now().Unix())
	}
	return value
}

func (s *Store) PutOrchestrator(ctx context.Context, value Orchestrator) error {
	value.ID = canonicalID(value.ID)
	value.PhysicalHostID = canonicalID(value.PhysicalHostID)
	value.HostNode = strings.TrimSpace(value.HostNode)
	value.HyperVName = strings.TrimSpace(value.HyperVName)
	value.NodeName = strings.TrimSpace(value.NodeName)
	value.CreatedAt = nowUnix(value.CreatedAt)
	value.UpdatedAt = nowUnix(value.UpdatedAt)
	if value.ID == "" || value.PhysicalHostID == "" || value.HostNode == "" ||
		value.HyperVName == "" || value.NodeName == "" {
		return errors.New("isolatedstate: incomplete orchestrator identity")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO orchestrators (
			id, display_name, physical_host_id, host_node, hyperv_name,
			hyperv_vm_id, node_name, profile_name, main_vswitch, main_mac,
			main_ip, agent_port, appliance_schema, desired_generation,
			applied_generation, observed_generation, host_fence, lifecycle_state,
			health_state, max_networks, max_vms, created_at_unix,
			updated_at_unix, last_seen_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			display_name=excluded.display_name,
			physical_host_id=excluded.physical_host_id,
			host_node=excluded.host_node,
			hyperv_name=excluded.hyperv_name,
			hyperv_vm_id=excluded.hyperv_vm_id,
			node_name=excluded.node_name,
			profile_name=excluded.profile_name,
			main_vswitch=excluded.main_vswitch,
			main_mac=excluded.main_mac,
			main_ip=excluded.main_ip,
			agent_port=excluded.agent_port,
			appliance_schema=excluded.appliance_schema,
			desired_generation=excluded.desired_generation,
			applied_generation=excluded.applied_generation,
			observed_generation=excluded.observed_generation,
			host_fence=excluded.host_fence,
			lifecycle_state=excluded.lifecycle_state,
			health_state=excluded.health_state,
			max_networks=excluded.max_networks,
			max_vms=excluded.max_vms,
			updated_at_unix=excluded.updated_at_unix,
			last_seen_unix=excluded.last_seen_unix`,
		value.ID, value.DisplayName, value.PhysicalHostID, value.HostNode,
		value.HyperVName, value.HyperVVMID, value.NodeName, value.ProfileName,
		value.MainVSwitch, value.MainMAC, value.MainIP, value.AgentPort,
		value.ApplianceSchema, value.DesiredGeneration, value.AppliedGeneration,
		value.ObservedGeneration, value.HostFence, value.LifecycleState,
		value.HealthState, value.MaxNetworks, value.MaxVMs, value.CreatedAt,
		value.UpdatedAt, value.LastSeenAt)
	if err != nil {
		return fmt.Errorf("isolatedstate: put orchestrator: %w", err)
	}
	return nil
}

func (s *Store) GetOrchestrator(ctx context.Context, id string) (Orchestrator, error) {
	var value Orchestrator
	err := s.db.QueryRowContext(ctx, `
		SELECT id, display_name, physical_host_id, host_node, hyperv_name,
		       hyperv_vm_id, node_name, profile_name, main_vswitch, main_mac,
		       main_ip, agent_port, appliance_schema, desired_generation,
		       applied_generation, observed_generation, host_fence,
		       lifecycle_state, health_state, max_networks, max_vms,
		       created_at_unix, updated_at_unix, last_seen_unix
		FROM orchestrators WHERE id=?`, canonicalID(id)).Scan(
		&value.ID, &value.DisplayName, &value.PhysicalHostID, &value.HostNode,
		&value.HyperVName, &value.HyperVVMID, &value.NodeName, &value.ProfileName,
		&value.MainVSwitch, &value.MainMAC, &value.MainIP, &value.AgentPort,
		&value.ApplianceSchema, &value.DesiredGeneration, &value.AppliedGeneration,
		&value.ObservedGeneration, &value.HostFence, &value.LifecycleState,
		&value.HealthState, &value.MaxNetworks, &value.MaxVMs, &value.CreatedAt,
		&value.UpdatedAt, &value.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Orchestrator{}, ErrOrchestratorNotFound
	}
	if err != nil {
		return Orchestrator{}, fmt.Errorf("isolatedstate: get orchestrator: %w", err)
	}
	return value, nil
}

func (s *Store) ListOrchestrators(ctx context.Context, physicalHostID string) ([]Orchestrator, error) {
	query := `
		SELECT id, display_name, physical_host_id, host_node, hyperv_name,
		       hyperv_vm_id, node_name, profile_name, main_vswitch, main_mac,
		       main_ip, agent_port, appliance_schema, desired_generation,
		       applied_generation, observed_generation, host_fence,
		       lifecycle_state, health_state, max_networks, max_vms,
		       created_at_unix, updated_at_unix, last_seen_unix
		FROM orchestrators`
	var args []any
	if physicalHostID = canonicalID(physicalHostID); physicalHostID != "" {
		query += " WHERE physical_host_id=?"
		args = append(args, physicalHostID)
	}
	query += " ORDER BY created_at_unix, id"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("isolatedstate: list orchestrators: %w", err)
	}
	defer rows.Close()
	var values []Orchestrator
	for rows.Next() {
		var value Orchestrator
		if err := rows.Scan(
			&value.ID, &value.DisplayName, &value.PhysicalHostID, &value.HostNode,
			&value.HyperVName, &value.HyperVVMID, &value.NodeName, &value.ProfileName,
			&value.MainVSwitch, &value.MainMAC, &value.MainIP, &value.AgentPort,
			&value.ApplianceSchema, &value.DesiredGeneration, &value.AppliedGeneration,
			&value.ObservedGeneration, &value.HostFence, &value.LifecycleState,
			&value.HealthState, &value.MaxNetworks, &value.MaxVMs, &value.CreatedAt,
			&value.UpdatedAt, &value.LastSeenAt); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) PutNetwork(ctx context.Context, value PrivateNetwork) error {
	value.ID = canonicalID(value.ID)
	value.OrchestratorID = canonicalID(value.OrchestratorID)
	value.CreatedAt = nowUnix(value.CreatedAt)
	value.UpdatedAt = nowUnix(value.UpdatedAt)
	if value.ID == "" || value.OrchestratorID == "" {
		return errors.New("isolatedstate: incomplete network identity")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO private_networks (
			id, orchestrator_id, display_name, hyperv_switch_name,
			hyperv_switch_guid, orchestrator_adapter_id, subnet_index, cidr,
			gateway_ipv4, orchestrator_mac, dns_servers_json,
			desired_generation, applied_generation, observed_generation,
			lifecycle_state, created_at_unix, updated_at_unix, retired_at_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			display_name=excluded.display_name,
			hyperv_switch_name=excluded.hyperv_switch_name,
			hyperv_switch_guid=excluded.hyperv_switch_guid,
			orchestrator_adapter_id=excluded.orchestrator_adapter_id,
			subnet_index=excluded.subnet_index,
			cidr=excluded.cidr,
			gateway_ipv4=excluded.gateway_ipv4,
			orchestrator_mac=excluded.orchestrator_mac,
			dns_servers_json=excluded.dns_servers_json,
			desired_generation=excluded.desired_generation,
			applied_generation=excluded.applied_generation,
			observed_generation=excluded.observed_generation,
			lifecycle_state=excluded.lifecycle_state,
			updated_at_unix=excluded.updated_at_unix,
			retired_at_unix=excluded.retired_at_unix`,
		value.ID, value.OrchestratorID, value.DisplayName, value.HyperVSwitchName,
		value.HyperVSwitchGUID, value.OrchestratorAdapterID, value.SubnetIndex,
		value.CIDR, value.GatewayIPv4, value.OrchestratorMAC, value.DNSServersJSON,
		value.DesiredGeneration, value.AppliedGeneration, value.ObservedGeneration,
		value.LifecycleState, value.CreatedAt, value.UpdatedAt, value.RetiredAt)
	if err != nil {
		return fmt.Errorf("isolatedstate: put network: %w", err)
	}
	return nil
}

func (s *Store) GetNetwork(ctx context.Context, id string) (PrivateNetwork, error) {
	var value PrivateNetwork
	err := s.db.QueryRowContext(ctx, `
		SELECT id, orchestrator_id, display_name, hyperv_switch_name,
		       hyperv_switch_guid, orchestrator_adapter_id, subnet_index, cidr,
		       gateway_ipv4, orchestrator_mac, dns_servers_json,
		       desired_generation, applied_generation, observed_generation,
		       lifecycle_state, created_at_unix, updated_at_unix, retired_at_unix
		FROM private_networks WHERE id=?`, canonicalID(id)).Scan(
		&value.ID, &value.OrchestratorID, &value.DisplayName,
		&value.HyperVSwitchName, &value.HyperVSwitchGUID,
		&value.OrchestratorAdapterID, &value.SubnetIndex, &value.CIDR,
		&value.GatewayIPv4, &value.OrchestratorMAC, &value.DNSServersJSON,
		&value.DesiredGeneration, &value.AppliedGeneration,
		&value.ObservedGeneration, &value.LifecycleState, &value.CreatedAt,
		&value.UpdatedAt, &value.RetiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return PrivateNetwork{}, ErrNetworkNotFound
	}
	if err != nil {
		return PrivateNetwork{}, fmt.Errorf("isolatedstate: get network: %w", err)
	}
	return value, nil
}

func (s *Store) ListNetworks(ctx context.Context, orchestratorID string) ([]PrivateNetwork, error) {
	query := `
		SELECT id, orchestrator_id, display_name, hyperv_switch_name,
		       hyperv_switch_guid, orchestrator_adapter_id, subnet_index, cidr,
		       gateway_ipv4, orchestrator_mac, dns_servers_json,
		       desired_generation, applied_generation, observed_generation,
		       lifecycle_state, created_at_unix, updated_at_unix, retired_at_unix
		FROM private_networks`
	var args []any
	if orchestratorID = canonicalID(orchestratorID); orchestratorID != "" {
		query += " WHERE orchestrator_id=?"
		args = append(args, orchestratorID)
	}
	query += " ORDER BY created_at_unix, id"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []PrivateNetwork
	for rows.Next() {
		var value PrivateNetwork
		if err := rows.Scan(
			&value.ID, &value.OrchestratorID, &value.DisplayName,
			&value.HyperVSwitchName, &value.HyperVSwitchGUID,
			&value.OrchestratorAdapterID, &value.SubnetIndex, &value.CIDR,
			&value.GatewayIPv4, &value.OrchestratorMAC, &value.DNSServersJSON,
			&value.DesiredGeneration, &value.AppliedGeneration,
			&value.ObservedGeneration, &value.LifecycleState, &value.CreatedAt,
			&value.UpdatedAt, &value.RetiredAt); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) CountActiveVMs(ctx context.Context, networkID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM isolated_vms
		WHERE network_id=? AND lifecycle_state <> 'deleted' AND retired_at_unix IS NULL`,
		canonicalID(networkID)).Scan(&count)
	return count, err
}

func (s *Store) GetVM(ctx context.Context, id string) (IsolatedVM, error) {
	var value IsolatedVM
	err := s.db.QueryRowContext(ctx, `
		SELECT id, orchestrator_id, network_id, display_name, hyperv_name,
		       hyperv_vm_id, hyperv_adapter_id, incarnation, node_name,
		       guest_os, profile_name, ipv4, mac, prefix_length, gateway_ipv4,
		       dns_servers_json, storage_root, vm_path, vhd_path,
		       desired_generation, applied_generation, observed_generation,
		       lifecycle_state, created_at_unix, updated_at_unix, retired_at_unix
		FROM isolated_vms WHERE id=?`, canonicalID(id)).Scan(
		&value.ID, &value.OrchestratorID, &value.NetworkID, &value.DisplayName,
		&value.HyperVName, &value.HyperVVMID, &value.HyperVAdapterID,
		&value.Incarnation, &value.NodeName, &value.GuestOS, &value.ProfileName,
		&value.IPv4, &value.MAC, &value.PrefixLength, &value.GatewayIPv4,
		&value.DNSServersJSON, &value.StorageRoot, &value.VMPath, &value.VHDPath,
		&value.DesiredGeneration, &value.AppliedGeneration,
		&value.ObservedGeneration, &value.LifecycleState, &value.CreatedAt,
		&value.UpdatedAt, &value.RetiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return IsolatedVM{}, ErrVMNotFound
	}
	if err != nil {
		return IsolatedVM{}, err
	}
	return value, nil
}

func (s *Store) ListVMs(ctx context.Context, orchestratorID, networkID string) ([]IsolatedVM, error) {
	query := `
		SELECT id, orchestrator_id, network_id, display_name, hyperv_name,
		       hyperv_vm_id, hyperv_adapter_id, incarnation, node_name,
		       guest_os, profile_name, ipv4, mac, prefix_length, gateway_ipv4,
		       dns_servers_json, storage_root, vm_path, vhd_path,
		       desired_generation, applied_generation, observed_generation,
		       lifecycle_state, created_at_unix, updated_at_unix, retired_at_unix
		FROM isolated_vms WHERE 1=1`
	var args []any
	if orchestratorID = canonicalID(orchestratorID); orchestratorID != "" {
		query += " AND orchestrator_id=?"
		args = append(args, orchestratorID)
	}
	if networkID = canonicalID(networkID); networkID != "" {
		query += " AND network_id=?"
		args = append(args, networkID)
	}
	query += " ORDER BY created_at_unix, id"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []IsolatedVM
	for rows.Next() {
		var value IsolatedVM
		if err := rows.Scan(
			&value.ID, &value.OrchestratorID, &value.NetworkID,
			&value.DisplayName, &value.HyperVName, &value.HyperVVMID,
			&value.HyperVAdapterID, &value.Incarnation, &value.NodeName,
			&value.GuestOS, &value.ProfileName, &value.IPv4, &value.MAC,
			&value.PrefixLength, &value.GatewayIPv4, &value.DNSServersJSON,
			&value.StorageRoot, &value.VMPath, &value.VHDPath,
			&value.DesiredGeneration, &value.AppliedGeneration,
			&value.ObservedGeneration, &value.LifecycleState, &value.CreatedAt,
			&value.UpdatedAt, &value.RetiredAt); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) PutRelay(ctx context.Context, value RelayAllocation) error {
	value.ID = canonicalID(value.ID)
	value.VMID = canonicalID(value.VMID)
	value.OrchestratorID = canonicalID(value.OrchestratorID)
	value.CreatedAt = nowUnix(value.CreatedAt)
	value.UpdatedAt = nowUnix(value.UpdatedAt)
	if value.TargetPort == 0 {
		value.TargetPort = 9091
	}
	if value.ID == "" || value.VMID == "" || value.OrchestratorID == "" ||
		value.TargetPort != 9091 {
		return errors.New("isolatedstate: invalid relay identity or target port")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO relay_allocations (
			id, vm_id, orchestrator_id, listen_port, target_ipv4, target_port,
			desired_generation, applied_generation, observed_generation,
			lifecycle_state, created_at_unix, updated_at_unix, retired_at_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			listen_port=excluded.listen_port,
			target_ipv4=excluded.target_ipv4,
			target_port=excluded.target_port,
			desired_generation=excluded.desired_generation,
			applied_generation=excluded.applied_generation,
			observed_generation=excluded.observed_generation,
			lifecycle_state=excluded.lifecycle_state,
			updated_at_unix=excluded.updated_at_unix,
			retired_at_unix=excluded.retired_at_unix`,
		value.ID, value.VMID, value.OrchestratorID, value.ListenPort,
		value.TargetIPv4, value.TargetPort, value.DesiredGeneration,
		value.AppliedGeneration, value.ObservedGeneration, value.LifecycleState,
		value.CreatedAt, value.UpdatedAt, value.RetiredAt)
	if err != nil {
		return fmt.Errorf("isolatedstate: put relay: %w", err)
	}
	return nil
}

func (s *Store) GetRelay(ctx context.Context, id string) (RelayAllocation, error) {
	var value RelayAllocation
	err := s.db.QueryRowContext(ctx, `
		SELECT id, vm_id, orchestrator_id, listen_port, target_ipv4,
		       target_port, desired_generation, applied_generation,
		       observed_generation, lifecycle_state, created_at_unix,
		       updated_at_unix, retired_at_unix
		FROM relay_allocations WHERE id=?`, canonicalID(id)).Scan(
		&value.ID, &value.VMID, &value.OrchestratorID, &value.ListenPort,
		&value.TargetIPv4, &value.TargetPort, &value.DesiredGeneration,
		&value.AppliedGeneration, &value.ObservedGeneration,
		&value.LifecycleState, &value.CreatedAt, &value.UpdatedAt,
		&value.RetiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RelayAllocation{}, ErrRelayNotFound
	}
	if err != nil {
		return RelayAllocation{}, err
	}
	return value, nil
}

func (s *Store) GetRelayForVM(ctx context.Context, vmID string) (RelayAllocation, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `
		SELECT id FROM relay_allocations
		WHERE vm_id=? AND retired_at_unix IS NULL LIMIT 1`,
		canonicalID(vmID)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return RelayAllocation{}, ErrRelayNotFound
	}
	if err != nil {
		return RelayAllocation{}, err
	}
	return s.GetRelay(ctx, id)
}

func (s *Store) ListRelays(ctx context.Context, orchestratorID, networkID string) ([]RelayAllocation, error) {
	query := `
		SELECT r.id, r.vm_id, r.orchestrator_id, r.listen_port, r.target_ipv4,
		       r.target_port, r.desired_generation, r.applied_generation,
		       r.observed_generation, r.lifecycle_state, r.created_at_unix,
		       r.updated_at_unix, r.retired_at_unix
		FROM relay_allocations r
		JOIN isolated_vms v ON v.id=r.vm_id
		WHERE 1=1`
	var args []any
	if orchestratorID = canonicalID(orchestratorID); orchestratorID != "" {
		query += " AND r.orchestrator_id=?"
		args = append(args, orchestratorID)
	}
	if networkID = canonicalID(networkID); networkID != "" {
		query += " AND v.network_id=?"
		args = append(args, networkID)
	}
	query += " ORDER BY r.created_at_unix, r.id"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []RelayAllocation
	for rows.Next() {
		var value RelayAllocation
		if err := rows.Scan(
			&value.ID, &value.VMID, &value.OrchestratorID, &value.ListenPort,
			&value.TargetIPv4, &value.TargetPort, &value.DesiredGeneration,
			&value.AppliedGeneration, &value.ObservedGeneration,
			&value.LifecycleState, &value.CreatedAt, &value.UpdatedAt,
			&value.RetiredAt); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) PutApprovalPlan(ctx context.Context, value ApprovalPlan) error {
	value.Revision = strings.TrimSpace(value.Revision)
	value.OperationID = canonicalID(value.OperationID)
	if value.Revision == "" || value.OperationID == "" || value.PlanHash == "" {
		return errors.New("isolatedstate: incomplete approval plan")
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO approval_plans (
			revision, operation_id, action, plan_json, plan_hash, state,
			approved_at_unix, consumed_at_unix
		) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(revision) DO UPDATE SET
			action=excluded.action,
			plan_json=excluded.plan_json,
			plan_hash=excluded.plan_hash
		WHERE approval_plans.operation_id=excluded.operation_id
		  AND approval_plans.plan_hash=excluded.plan_hash`,
		value.Revision, value.OperationID, value.Action, value.PlanJSON,
		value.PlanHash, value.State, value.ApprovedAt, value.ConsumedAt)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("isolatedstate: approval revision already belongs to different immutable plan")
	}
	return nil
}

func (s *Store) GetApprovalPlan(ctx context.Context, revision string) (ApprovalPlan, error) {
	var value ApprovalPlan
	err := s.db.QueryRowContext(ctx, `
		SELECT revision, operation_id, action, plan_json, plan_hash, state,
		       approved_at_unix, consumed_at_unix
		FROM approval_plans WHERE revision=?`, strings.TrimSpace(revision)).Scan(
		&value.Revision, &value.OperationID, &value.Action, &value.PlanJSON,
		&value.PlanHash, &value.State, &value.ApprovedAt, &value.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalPlan{}, ErrApprovalNotFound
	}
	return value, err
}

func (s *Store) ApprovePlan(ctx context.Context, operationID, revision, planHash string) error {
	now := UnixSeconds(time.Now().Unix())
	result, err := s.db.ExecContext(ctx, `
		UPDATE approval_plans
		SET state=?, approved_at_unix=?
		WHERE revision=? AND operation_id=? AND plan_hash=?
		  AND state IN (?,?)`,
		ApprovalApproved, now, strings.TrimSpace(revision), canonicalID(operationID),
		strings.TrimSpace(planHash), ApprovalPending, ApprovalApproved)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrApprovalNotFound
	}
	return nil
}

func (s *Store) ConsumePlan(ctx context.Context, operationID, revision, planHash string) error {
	now := UnixSeconds(time.Now().Unix())
	result, err := s.db.ExecContext(ctx, `
		UPDATE approval_plans
		SET state=?, consumed_at_unix=?
		WHERE revision=? AND operation_id=? AND plan_hash=? AND state=?`,
		ApprovalConsumed, now, strings.TrimSpace(revision),
		canonicalID(operationID), strings.TrimSpace(planHash), ApprovalApproved)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("isolatedstate: approval is missing, stale, or already consumed")
	}
	return nil
}
