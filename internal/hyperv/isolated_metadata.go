package hyperv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	IsolatedMetadataSchema             = 1
	IsolatedOrchestratorMetadataPrefix = "LABLINK_ISOLATED_ORCHESTRATOR:"
	IsolatedVMMetadataPrefix           = "LABLINK_ISOLATED_VM:"
	IsolatedOwnerMarkerPrefix          = "lablink-isolated/"
)

var (
	isolatedUUIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hostIDRE       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	macRE          = regexp.MustCompile(`^[0-9A-F]{12}$`)
)

// CascadeAuthority is the revision-bound cleanup capability installed when an
// orchestrator is frozen. It authorizes only the enumerated actions.
type CascadeAuthority struct {
	OrchestratorID   string                 `json:"orchestrator_id"`
	FrozenGeneration int64                  `json:"frozen_generation"`
	OperationID      string                 `json:"operation_id"`
	PlanRevision     string                 `json:"plan_revision"`
	PlanHash         string                 `json:"plan_hash"`
	HostFence        int64                  `json:"host_fence"`
	LeaseID          string                 `json:"lease_id"`
	Items            []CascadeAuthorityItem `json:"items"`
}

type CascadeAuthorityItem struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
	Generation   int64  `json:"generation"`
	SwitchGUID   string `json:"switch_guid,omitempty"`
	VMGUID       string `json:"vm_guid,omitempty"`
	AdapterID    string `json:"adapter_id,omitempty"`
	Completed    bool   `json:"completed"`
}

// IsolatedOrchestratorMetadata is persisted in the orchestrator VM Notes.
// Physical IDs and infrastructure IDs are immutable reconciliation keys;
// display names are deliberately absent.
type IsolatedOrchestratorMetadata struct {
	SchemaVersion    int                  `json:"schema_version"`
	PhysicalHostID   string               `json:"physical_host_id"`
	OrchestratorID   string               `json:"orchestrator_id"`
	OwnerMarker      string               `json:"owner_marker"`
	HostFence        int64                `json:"host_fence"`
	LifecycleState   string               `json:"lifecycle_state"`
	ManagedRoot      string               `json:"managed_root"`
	ExpectedVHDPaths []string             `json:"expected_vhd_paths"`
	NodeName         string               `json:"node_name"`
	VMGUID           string               `json:"vm_guid"`
	Generation       int64                `json:"generation"`
	PrivateAdapters  []IsolatedAdapterRef `json:"private_adapters,omitempty"`
	CascadeAuthority *CascadeAuthority    `json:"cascade_authority,omitempty"`
}

// IsolatedVMMetadata is persisted in an isolated guest VM's Notes.
type IsolatedVMMetadata struct {
	SchemaVersion    int               `json:"schema_version"`
	PhysicalHostID   string            `json:"physical_host_id"`
	OrchestratorID   string            `json:"orchestrator_id"`
	NetworkID        string            `json:"network_id"`
	VMID             string            `json:"vm_id"`
	RelayID          string            `json:"relay_id,omitempty"`
	OwnerMarker      string            `json:"owner_marker"`
	HostFence        int64             `json:"host_fence"`
	LifecycleState   string            `json:"lifecycle_state"`
	ManagedRoot      string            `json:"managed_root"`
	ExpectedVHDPaths []string          `json:"expected_vhd_paths"`
	NodeName         string            `json:"node_name"`
	IPv4             string            `json:"ipv4"`
	MAC              string            `json:"mac"`
	SwitchGUID       string            `json:"switch_guid"`
	VMGUID           string            `json:"vm_guid"`
	AdapterID        string            `json:"adapter_id"`
	Incarnation      int64             `json:"incarnation"`
	Generation       int64             `json:"generation"`
	CascadeAuthority *CascadeAuthority `json:"cascade_authority,omitempty"`
}

type IsolatedAdapterRef struct {
	NetworkID  string `json:"network_id"`
	AdapterID  string `json:"adapter_id"`
	MAC        string `json:"mac"`
	SwitchGUID string `json:"switch_guid"`
}

// IsolatedNetworkMetadata is the host-side ownership record for one private
// switch and its orchestrator adapter.
type IsolatedNetworkMetadata struct {
	SchemaVersion         int    `json:"schema_version"`
	PhysicalHostID        string `json:"physical_host_id"`
	OrchestratorID        string `json:"orchestrator_id"`
	NetworkID             string `json:"network_id"`
	OwnerMarker           string `json:"owner_marker"`
	HostFence             int64  `json:"host_fence"`
	MutationID            string `json:"mutation_id"`
	Generation            int64  `json:"generation"`
	State                 string `json:"state"`
	SwitchName            string `json:"switch_name"`
	SwitchGUID            string `json:"switch_guid,omitempty"`
	OrchestratorVMGUID    string `json:"orchestrator_vm_guid,omitempty"`
	OrchestratorAdapter   string `json:"orchestrator_adapter_name,omitempty"`
	OrchestratorAdapterID string `json:"orchestrator_adapter_id,omitempty"`
	OrchestratorMAC       string `json:"orchestrator_mac,omitempty"`
}

type IsolatedAdapterMetadata struct {
	SchemaVersion  int    `json:"schema_version"`
	PhysicalHostID string `json:"physical_host_id"`
	OrchestratorID string `json:"orchestrator_id"`
	NetworkID      string `json:"network_id"`
	ResourceID     string `json:"resource_id"`
	ResourceType   string `json:"resource_type"`
	OwnerMarker    string `json:"owner_marker"`
	HostFence      int64  `json:"host_fence"`
	MutationID     string `json:"mutation_id"`
	Generation     int64  `json:"generation"`
	State          string `json:"state"`
	VMGUID         string `json:"vm_guid"`
	AdapterName    string `json:"adapter_name"`
	AdapterID      string `json:"adapter_id,omitempty"`
	MAC            string `json:"mac"`
	SwitchGUID     string `json:"switch_guid"`
}

func IsolatedOwnerMarker(orchestratorID, resourceType, resourceID string) (string, error) {
	if err := validateIsolatedID("orchestrator", orchestratorID); err != nil {
		return "", err
	}
	if err := validateIsolatedID(resourceType, resourceID); err != nil {
		return "", err
	}
	resourceType = strings.ToLower(strings.TrimSpace(resourceType))
	if resourceType == "" || strings.ContainsAny(resourceType, "/\\\x00\r\n") {
		return "", fmt.Errorf("invalid isolated resource type %q", resourceType)
	}
	return IsolatedOwnerMarkerPrefix + orchestratorID + "/" + resourceType + "/" + resourceID, nil
}

// DeterministicIsolatedMAC returns a locally administered unicast MAC in the
// format accepted by Hyper-V's StaticMacAddress parameter.
func DeterministicIsolatedMAC(resourceID string) (string, error) {
	if err := validateIsolatedID("resource", resourceID); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte("lablink-isolated-mac/v1\x00" + resourceID))
	value := []byte{0x02, 0x15, 0x5d, sum[0], sum[1], sum[2]}
	return strings.ToUpper(hex.EncodeToString(value)), nil
}

func MarshalIsolatedOrchestratorMetadata(metadata IsolatedOrchestratorMetadata) (string, error) {
	if metadata.SchemaVersion == 0 {
		metadata.SchemaVersion = IsolatedMetadataSchema
	}
	if err := validateOrchestratorMetadata(metadata); err != nil {
		return "", err
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return IsolatedOrchestratorMetadataPrefix + string(data), nil
}

func ParseIsolatedOrchestratorMetadata(notes string) (IsolatedOrchestratorMetadata, error) {
	var metadata IsolatedOrchestratorMetadata
	if !strings.HasPrefix(notes, IsolatedOrchestratorMetadataPrefix) {
		return metadata, fmt.Errorf("isolated orchestrator metadata prefix missing")
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(notes, IsolatedOrchestratorMetadataPrefix)), &metadata); err != nil {
		return metadata, err
	}
	return metadata, validateOrchestratorMetadata(metadata)
}

func MarshalIsolatedVMMetadata(metadata IsolatedVMMetadata) (string, error) {
	if metadata.SchemaVersion == 0 {
		metadata.SchemaVersion = IsolatedMetadataSchema
	}
	if err := validateVMMetadata(metadata); err != nil {
		return "", err
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return IsolatedVMMetadataPrefix + string(data), nil
}

func ParseIsolatedVMMetadata(notes string) (IsolatedVMMetadata, error) {
	var metadata IsolatedVMMetadata
	if !strings.HasPrefix(notes, IsolatedVMMetadataPrefix) {
		return metadata, fmt.Errorf("isolated VM metadata prefix missing")
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(notes, IsolatedVMMetadataPrefix)), &metadata); err != nil {
		return metadata, err
	}
	return metadata, validateVMMetadata(metadata)
}

func MarshalIsolatedNetworkMetadata(metadata IsolatedNetworkMetadata) (string, error) {
	if metadata.SchemaVersion == 0 {
		metadata.SchemaVersion = IsolatedMetadataSchema
	}
	if err := validateNetworkMetadata(metadata); err != nil {
		return "", err
	}
	data, err := json.Marshal(metadata)
	return string(data), err
}

func ParseIsolatedNetworkMetadata(data string) (IsolatedNetworkMetadata, error) {
	var metadata IsolatedNetworkMetadata
	if err := json.Unmarshal([]byte(data), &metadata); err != nil {
		return metadata, err
	}
	return metadata, validateNetworkMetadata(metadata)
}

func MarshalIsolatedAdapterMetadata(metadata IsolatedAdapterMetadata) (string, error) {
	if metadata.SchemaVersion == 0 {
		metadata.SchemaVersion = IsolatedMetadataSchema
	}
	if err := validateAdapterMetadata(metadata); err != nil {
		return "", err
	}
	data, err := json.Marshal(metadata)
	return string(data), err
}

func validateOrchestratorMetadata(m IsolatedOrchestratorMetadata) error {
	if m.SchemaVersion != IsolatedMetadataSchema {
		return fmt.Errorf("unsupported isolated metadata schema %d", m.SchemaVersion)
	}
	if err := validateHostID(m.PhysicalHostID); err != nil {
		return err
	}
	if err := validateIsolatedID("orchestrator", m.OrchestratorID); err != nil {
		return err
	}
	if err := validateOwnerMarker(m.OwnerMarker, m.OrchestratorID); err != nil {
		return err
	}
	if m.HostFence <= 0 || m.Generation <= 0 || strings.TrimSpace(m.LifecycleState) == "" ||
		strings.TrimSpace(m.ManagedRoot) == "" || strings.TrimSpace(m.NodeName) == "" ||
		len(m.ExpectedVHDPaths) == 0 {
		return fmt.Errorf("incomplete isolated orchestrator metadata")
	}
	if m.VMGUID != "" {
		if err := validateGUID("VM", m.VMGUID); err != nil {
			return err
		}
	}
	return validateCascadeAuthority(m.CascadeAuthority)
}

func validateVMMetadata(m IsolatedVMMetadata) error {
	if m.SchemaVersion != IsolatedMetadataSchema {
		return fmt.Errorf("unsupported isolated metadata schema %d", m.SchemaVersion)
	}
	if err := validateHostID(m.PhysicalHostID); err != nil {
		return err
	}
	for kind, value := range map[string]string{
		"orchestrator": m.OrchestratorID,
		"network":      m.NetworkID,
		"VM":           m.VMID,
	} {
		if err := validateIsolatedID(kind, value); err != nil {
			return err
		}
	}
	if m.RelayID != "" {
		if err := validateIsolatedID("relay", m.RelayID); err != nil {
			return err
		}
	}
	if err := validateOwnerMarker(m.OwnerMarker, m.OrchestratorID); err != nil {
		return err
	}
	if m.HostFence <= 0 || m.Generation <= 0 || m.Incarnation <= 0 ||
		strings.TrimSpace(m.LifecycleState) == "" || strings.TrimSpace(m.ManagedRoot) == "" ||
		strings.TrimSpace(m.NodeName) == "" || strings.TrimSpace(m.IPv4) == "" ||
		len(m.ExpectedVHDPaths) == 0 {
		return fmt.Errorf("incomplete isolated VM metadata")
	}
	if !macRE.MatchString(strings.ToUpper(strings.ReplaceAll(m.MAC, "-", ""))) {
		return fmt.Errorf("invalid isolated VM MAC %q", m.MAC)
	}
	for kind, value := range map[string]string{"switch": m.SwitchGUID, "VM": m.VMGUID, "adapter": m.AdapterID} {
		if value != "" {
			if err := validateGUID(kind, value); err != nil {
				return err
			}
		}
	}
	if m.LifecycleState == "ready" || m.LifecycleState == "repairing" || m.LifecycleState == "degraded" {
		if m.SwitchGUID == "" || m.VMGUID == "" || m.AdapterID == "" {
			return fmt.Errorf("live isolated VM metadata requires switch, VM, and adapter IDs")
		}
	}
	return validateCascadeAuthority(m.CascadeAuthority)
}

func validateNetworkMetadata(m IsolatedNetworkMetadata) error {
	if m.SchemaVersion != IsolatedMetadataSchema {
		return fmt.Errorf("unsupported isolated metadata schema %d", m.SchemaVersion)
	}
	if err := validateHostID(m.PhysicalHostID); err != nil {
		return err
	}
	for kind, value := range map[string]string{"orchestrator": m.OrchestratorID, "network": m.NetworkID, "mutation": m.MutationID} {
		if err := validateIsolatedID(kind, value); err != nil {
			return err
		}
	}
	if err := validateOwnerMarker(m.OwnerMarker, m.OrchestratorID); err != nil {
		return err
	}
	if m.HostFence <= 0 || m.Generation <= 0 || strings.TrimSpace(m.State) == "" || strings.TrimSpace(m.SwitchName) == "" {
		return fmt.Errorf("incomplete isolated network metadata")
	}
	for kind, value := range map[string]string{
		"switch":  m.SwitchGUID,
		"VM":      m.OrchestratorVMGUID,
		"adapter": m.OrchestratorAdapterID,
	} {
		if value != "" {
			if err := validateGUID(kind, value); err != nil {
				return err
			}
		}
	}
	if m.OrchestratorMAC != "" && !macRE.MatchString(strings.ToUpper(strings.ReplaceAll(m.OrchestratorMAC, "-", ""))) {
		return fmt.Errorf("invalid orchestrator MAC %q", m.OrchestratorMAC)
	}
	return nil
}

func validateAdapterMetadata(m IsolatedAdapterMetadata) error {
	if m.SchemaVersion != IsolatedMetadataSchema {
		return fmt.Errorf("unsupported isolated metadata schema %d", m.SchemaVersion)
	}
	if err := validateHostID(m.PhysicalHostID); err != nil {
		return err
	}
	for kind, value := range map[string]string{
		"orchestrator": m.OrchestratorID,
		"network":      m.NetworkID,
		"resource":     m.ResourceID,
		"mutation":     m.MutationID,
	} {
		if err := validateIsolatedID(kind, value); err != nil {
			return err
		}
	}
	if err := validateOwnerMarker(m.OwnerMarker, m.OrchestratorID); err != nil {
		return err
	}
	if m.HostFence <= 0 || m.Generation <= 0 || strings.TrimSpace(m.ResourceType) == "" ||
		strings.TrimSpace(m.State) == "" || strings.TrimSpace(m.AdapterName) == "" {
		return fmt.Errorf("incomplete isolated adapter metadata")
	}
	for kind, value := range map[string]string{"VM": m.VMGUID, "switch": m.SwitchGUID} {
		if err := validateGUID(kind, value); err != nil {
			return err
		}
	}
	if m.AdapterID != "" {
		if err := validateGUID("adapter", m.AdapterID); err != nil {
			return err
		}
	}
	if !macRE.MatchString(strings.ToUpper(strings.ReplaceAll(m.MAC, "-", ""))) {
		return fmt.Errorf("invalid adapter MAC %q", m.MAC)
	}
	return nil
}

func validateCascadeAuthority(authority *CascadeAuthority) error {
	if authority == nil {
		return nil
	}
	if err := validateIsolatedID("orchestrator", authority.OrchestratorID); err != nil {
		return err
	}
	if err := validateIsolatedID("operation", authority.OperationID); err != nil {
		return err
	}
	if err := validateIsolatedID("lease", authority.LeaseID); err != nil {
		return err
	}
	if authority.FrozenGeneration <= 0 || authority.HostFence <= 0 ||
		strings.TrimSpace(authority.PlanRevision) == "" || strings.TrimSpace(authority.PlanHash) == "" ||
		len(authority.Items) == 0 {
		return fmt.Errorf("incomplete cascade authority")
	}
	for _, item := range authority.Items {
		if err := validateIsolatedID(item.ResourceType, item.ResourceID); err != nil {
			return err
		}
		if !isCascadeCleanupAction(item.Action) || item.Generation <= 0 {
			return fmt.Errorf("incomplete cascade authority item")
		}
	}
	return nil
}

func isCascadeCleanupAction(action string) bool {
	switch action {
	case "delete_private_switch", "remove_nic", "delete_vm", "delete_storage",
		"retire_relay", "retire_nat", "remove_network", "tombstone_allocation":
		return true
	default:
		return false
	}
}

func validateHostID(value string) error {
	if !hostIDRE.MatchString(value) {
		return fmt.Errorf("invalid physical host ID %q", value)
	}
	return nil
}

func validateIsolatedID(kind, value string) error {
	if !isolatedUUIDRE.MatchString(strings.ToLower(strings.TrimSpace(value))) {
		return fmt.Errorf("invalid %s ID %q", kind, value)
	}
	return nil
}

func validateGUID(kind, value string) error {
	value = strings.Trim(strings.ToLower(strings.TrimSpace(value)), "{}")
	if !isolatedUUIDRE.MatchString(value) {
		return fmt.Errorf("invalid %s GUID %q", kind, value)
	}
	return nil
}

func validateOwnerMarker(marker, orchestratorID string) error {
	if !strings.HasPrefix(marker, IsolatedOwnerMarkerPrefix+orchestratorID+"/") {
		return fmt.Errorf("owner marker %q does not belong to orchestrator %s", marker, orchestratorID)
	}
	return nil
}
