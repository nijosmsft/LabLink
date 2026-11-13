package isolatedstate

import (
	"context"
	"database/sql"
)

func (s *Store) PutOrchestrator(ctx context.Context, v Orchestrator) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO orchestrators (
			id,display_name,physical_host_id,host_node,hyperv_name,hyperv_vm_id,
			node_name,profile_name,main_vswitch,main_mac,main_ip,agent_port,
			appliance_schema,lifecycle_state,health_state,max_networks,max_vms,
			created_at_unix,updated_at_unix,last_seen_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
			lifecycle_state=excluded.lifecycle_state,
			health_state=excluded.health_state,
			max_networks=excluded.max_networks,
			max_vms=excluded.max_vms,
			updated_at_unix=excluded.updated_at_unix,
			last_seen_unix=excluded.last_seen_unix
	`, v.ID, v.DisplayName, v.PhysicalHostID, v.HostNode, v.HyperVName, v.HyperVVMID,
		v.NodeName, v.ProfileName, v.MainVSwitch, v.MainMAC, v.MainIP, v.AgentPort,
		v.ApplianceSchema, v.LifecycleState, v.HealthState, v.MaxNetworks, v.MaxVMs,
		v.CreatedAt, v.UpdatedAt, v.LastSeenAt)
	return err
}

func (s *Store) GetOrchestrator(ctx context.Context, id string) (Orchestrator, error) {
	var v Orchestrator
	err := s.db.QueryRowContext(ctx, `
		SELECT id,display_name,physical_host_id,host_node,hyperv_name,hyperv_vm_id,
			node_name,profile_name,main_vswitch,main_mac,main_ip,agent_port,
			appliance_schema,lifecycle_state,health_state,max_networks,max_vms,
			created_at_unix,updated_at_unix,last_seen_unix
		FROM orchestrators WHERE id=?
	`, id).Scan(&v.ID, &v.DisplayName, &v.PhysicalHostID, &v.HostNode, &v.HyperVName,
		&v.HyperVVMID, &v.NodeName, &v.ProfileName, &v.MainVSwitch, &v.MainMAC,
		&v.MainIP, &v.AgentPort, &v.ApplianceSchema, &v.LifecycleState, &v.HealthState,
		&v.MaxNetworks, &v.MaxVMs, &v.CreatedAt, &v.UpdatedAt, &v.LastSeenAt)
	return v, noRows("orchestrator", id, err)
}

func (s *Store) ListOrchestrators(ctx context.Context, host string) ([]Orchestrator, error) {
	query := `SELECT id,display_name,physical_host_id,host_node,hyperv_name,hyperv_vm_id,
		node_name,profile_name,main_vswitch,main_mac,main_ip,agent_port,
		appliance_schema,lifecycle_state,health_state,max_networks,max_vms,
		created_at_unix,updated_at_unix,last_seen_unix FROM orchestrators`
	var args []any
	if host != "" {
		query += ` WHERE physical_host_id=? OR host_node=?`
		args = append(args, host, host)
	}
	query += ` ORDER BY created_at_unix,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []Orchestrator
	for rows.Next() {
		var v Orchestrator
		if err := rows.Scan(&v.ID, &v.DisplayName, &v.PhysicalHostID, &v.HostNode,
			&v.HyperVName, &v.HyperVVMID, &v.NodeName, &v.ProfileName, &v.MainVSwitch,
			&v.MainMAC, &v.MainIP, &v.AgentPort, &v.ApplianceSchema, &v.LifecycleState,
			&v.HealthState, &v.MaxNetworks, &v.MaxVMs, &v.CreatedAt, &v.UpdatedAt,
			&v.LastSeenAt); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func (s *Store) PutNetwork(ctx context.Context, v PrivateNetwork) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO private_networks (
			id,orchestrator_id,display_name,hyperv_switch_name,hyperv_switch_guid,
			orchestrator_adapter_id,subnet_index,cidr,gateway_ipv4,orchestrator_mac,
			dns_servers_json,lifecycle_state,created_at_unix,updated_at_unix,retired_at_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			display_name=excluded.display_name,
			hyperv_switch_name=excluded.hyperv_switch_name,
			hyperv_switch_guid=excluded.hyperv_switch_guid,
			orchestrator_adapter_id=excluded.orchestrator_adapter_id,
			subnet_index=excluded.subnet_index,cidr=excluded.cidr,
			gateway_ipv4=excluded.gateway_ipv4,
			orchestrator_mac=excluded.orchestrator_mac,
			dns_servers_json=excluded.dns_servers_json,
			lifecycle_state=excluded.lifecycle_state,
			updated_at_unix=excluded.updated_at_unix,
			retired_at_unix=excluded.retired_at_unix
	`, v.ID, v.OrchestratorID, v.DisplayName, v.HyperVSwitchName, v.HyperVSwitchGUID,
		v.OrchestratorAdapterID, v.SubnetIndex, v.CIDR, v.GatewayIPv4,
		v.OrchestratorMAC, v.DNSServersJSON, v.LifecycleState,
		v.CreatedAt, v.UpdatedAt, v.RetiredAt)
	return err
}

func (s *Store) GetNetwork(ctx context.Context, id string) (PrivateNetwork, error) {
	var v PrivateNetwork
	err := s.db.QueryRowContext(ctx, `
		SELECT id,orchestrator_id,display_name,hyperv_switch_name,hyperv_switch_guid,
			orchestrator_adapter_id,subnet_index,cidr,gateway_ipv4,orchestrator_mac,
			dns_servers_json,lifecycle_state,created_at_unix,updated_at_unix,retired_at_unix
		FROM private_networks WHERE id=?
	`, id).Scan(&v.ID, &v.OrchestratorID, &v.DisplayName, &v.HyperVSwitchName,
		&v.HyperVSwitchGUID, &v.OrchestratorAdapterID, &v.SubnetIndex, &v.CIDR,
		&v.GatewayIPv4, &v.OrchestratorMAC, &v.DNSServersJSON, &v.LifecycleState,
		&v.CreatedAt, &v.UpdatedAt, &v.RetiredAt)
	return v, noRows("network", id, err)
}

func (s *Store) ListNetworks(ctx context.Context, orchestratorID string) ([]PrivateNetwork, error) {
	query := `SELECT id,orchestrator_id,display_name,hyperv_switch_name,hyperv_switch_guid,
		orchestrator_adapter_id,subnet_index,cidr,gateway_ipv4,orchestrator_mac,
		dns_servers_json,lifecycle_state,created_at_unix,updated_at_unix,retired_at_unix
		FROM private_networks`
	var args []any
	if orchestratorID != "" {
		query += ` WHERE orchestrator_id=?`
		args = append(args, orchestratorID)
	}
	query += ` ORDER BY created_at_unix,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []PrivateNetwork
	for rows.Next() {
		var v PrivateNetwork
		if err := rows.Scan(&v.ID, &v.OrchestratorID, &v.DisplayName, &v.HyperVSwitchName,
			&v.HyperVSwitchGUID, &v.OrchestratorAdapterID, &v.SubnetIndex, &v.CIDR,
			&v.GatewayIPv4, &v.OrchestratorMAC, &v.DNSServersJSON, &v.LifecycleState,
			&v.CreatedAt, &v.UpdatedAt, &v.RetiredAt); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func (s *Store) PutVM(ctx context.Context, v IsolatedVM) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO isolated_vms (
			id,orchestrator_id,network_id,display_name,hyperv_name,hyperv_vm_id,
			hyperv_adapter_id,node_name,guest_os,profile_name,ipv4,mac,prefix_length,
			gateway_ipv4,dns_servers_json,storage_root,vm_path,vhd_path,lifecycle_state,
			created_at_unix,updated_at_unix,retired_at_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			display_name=excluded.display_name,hyperv_name=excluded.hyperv_name,
			hyperv_vm_id=excluded.hyperv_vm_id,hyperv_adapter_id=excluded.hyperv_adapter_id,
			node_name=excluded.node_name,guest_os=excluded.guest_os,
			profile_name=excluded.profile_name,ipv4=excluded.ipv4,mac=excluded.mac,
			prefix_length=excluded.prefix_length,gateway_ipv4=excluded.gateway_ipv4,
			dns_servers_json=excluded.dns_servers_json,storage_root=excluded.storage_root,
			vm_path=excluded.vm_path,vhd_path=excluded.vhd_path,
			lifecycle_state=excluded.lifecycle_state,updated_at_unix=excluded.updated_at_unix,
			retired_at_unix=excluded.retired_at_unix
	`, v.ID, v.OrchestratorID, v.NetworkID, v.DisplayName, v.HyperVName, v.HyperVVMID,
		v.HyperVAdapterID, v.NodeName, v.GuestOS, v.ProfileName, v.IPv4, v.MAC,
		v.PrefixLength, v.GatewayIPv4, v.DNSServersJSON, v.StorageRoot, v.VMPath,
		v.VHDPath, v.LifecycleState, v.CreatedAt, v.UpdatedAt, v.RetiredAt)
	return err
}

func scanVM(scanner interface{ Scan(...any) error }) (IsolatedVM, error) {
	var v IsolatedVM
	err := scanner.Scan(&v.ID, &v.OrchestratorID, &v.NetworkID, &v.DisplayName,
		&v.HyperVName, &v.HyperVVMID, &v.HyperVAdapterID, &v.NodeName, &v.GuestOS,
		&v.ProfileName, &v.IPv4, &v.MAC, &v.PrefixLength, &v.GatewayIPv4,
		&v.DNSServersJSON, &v.StorageRoot, &v.VMPath, &v.VHDPath, &v.LifecycleState,
		&v.CreatedAt, &v.UpdatedAt, &v.RetiredAt)
	return v, err
}

const vmSelect = `SELECT id,orchestrator_id,network_id,display_name,hyperv_name,
	hyperv_vm_id,hyperv_adapter_id,node_name,guest_os,profile_name,ipv4,mac,
	prefix_length,gateway_ipv4,dns_servers_json,storage_root,vm_path,vhd_path,
	lifecycle_state,created_at_unix,updated_at_unix,retired_at_unix FROM isolated_vms`

func (s *Store) GetVM(ctx context.Context, id string) (IsolatedVM, error) {
	v, err := scanVM(s.db.QueryRowContext(ctx, vmSelect+` WHERE id=?`, id))
	return v, noRows("VM", id, err)
}

func (s *Store) ListVMs(ctx context.Context, orchestratorID, networkID string) ([]IsolatedVM, error) {
	query := vmSelect + ` WHERE 1=1`
	var args []any
	if orchestratorID != "" {
		query += ` AND orchestrator_id=?`
		args = append(args, orchestratorID)
	}
	if networkID != "" {
		query += ` AND network_id=?`
		args = append(args, networkID)
	}
	query += ` ORDER BY created_at_unix,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []IsolatedVM
	for rows.Next() {
		v, err := scanVM(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func (s *Store) CountActiveVMs(ctx context.Context, networkID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM isolated_vms WHERE network_id=? AND retired_at_unix IS NULL`, networkID).Scan(&count)
	return count, err
}

func (s *Store) PutRelay(ctx context.Context, v RelayAllocation) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO relay_allocations(id,vm_id,orchestrator_id,listen_port,target_ipv4,
			target_port,lifecycle_state,created_at_unix,updated_at_unix,retired_at_unix)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET listen_port=excluded.listen_port,
			target_ipv4=excluded.target_ipv4,target_port=excluded.target_port,
			lifecycle_state=excluded.lifecycle_state,updated_at_unix=excluded.updated_at_unix,
			retired_at_unix=excluded.retired_at_unix
	`, v.ID, v.VMID, v.OrchestratorID, v.ListenPort, v.TargetIPv4, v.TargetPort,
		v.LifecycleState, v.CreatedAt, v.UpdatedAt, v.RetiredAt)
	return err
}

const relaySelect = `SELECT id,vm_id,orchestrator_id,listen_port,target_ipv4,target_port,
	lifecycle_state,created_at_unix,updated_at_unix,retired_at_unix FROM relay_allocations`

func scanRelay(scanner interface{ Scan(...any) error }) (RelayAllocation, error) {
	var v RelayAllocation
	err := scanner.Scan(&v.ID, &v.VMID, &v.OrchestratorID, &v.ListenPort, &v.TargetIPv4,
		&v.TargetPort, &v.LifecycleState, &v.CreatedAt, &v.UpdatedAt, &v.RetiredAt)
	return v, err
}

func (s *Store) GetRelay(ctx context.Context, id string) (RelayAllocation, error) {
	v, err := scanRelay(s.db.QueryRowContext(ctx, relaySelect+` WHERE id=?`, id))
	return v, noRows("relay", id, err)
}
func (s *Store) GetRelayForVM(ctx context.Context, id string) (RelayAllocation, error) {
	v, err := scanRelay(s.db.QueryRowContext(ctx, relaySelect+` WHERE vm_id=? ORDER BY created_at_unix DESC LIMIT 1`, id))
	return v, noRows("relay for VM", id, err)
}
func (s *Store) ListRelays(ctx context.Context, orchestratorID, vmID string) ([]RelayAllocation, error) {
	query := relaySelect + ` WHERE 1=1`
	var args []any
	if orchestratorID != "" {
		query += ` AND orchestrator_id=?`
		args = append(args, orchestratorID)
	}
	if vmID != "" {
		query += ` AND vm_id=?`
		args = append(args, vmID)
	}
	query += ` ORDER BY created_at_unix,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []RelayAllocation
	for rows.Next() {
		v, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func scanNullableString(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	v := value.String
	return &v
}
