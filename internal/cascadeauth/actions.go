package cascadeauth

import (
	"fmt"
	"strings"
)

type Action string

const (
	ActionRelayRetire               Action = "retire_relay"
	ActionRelayRemove               Action = "remove_relay"
	ActionNATDisable                Action = "disable_nat"
	ActionNATReconcile              Action = "reconcile_nat"
	ActionGuestRemove               Action = "remove_guest"
	ActionGuestReleaseResources     Action = "release_guest_resources"
	ActionGuestDeleteExact          Action = "delete_isolated_vm"
	ActionAdapterMetadataReconcile  Action = "reconcile_adapter_metadata"
	ActionAdapterRemove             Action = "remove_nic"
	ActionPrivateSwitchDelete       Action = "delete_private_switch"
	ActionNetworkRemove             Action = "remove_network"
	ActionNetworkMetadataCleanup    Action = "cleanup_network_metadata"
	ActionOrchestratorMetadataClean Action = "cleanup_orchestrator_metadata"
	ActionOrchestratorVMDelete      Action = "delete_orchestrator_vm"
)

type Operation struct {
	ResourceType string
	Action       Action
}

var actionScopes = map[Action]string{
	ActionRelayRetire:               "relay",
	ActionRelayRemove:               "relay",
	ActionNATDisable:                "nat",
	ActionNATReconcile:              "nat",
	ActionGuestRemove:               "vm",
	ActionGuestReleaseResources:     "vm",
	ActionGuestDeleteExact:          "vm",
	ActionAdapterMetadataReconcile:  "network",
	ActionAdapterRemove:             "network",
	ActionPrivateSwitchDelete:       "network",
	ActionNetworkRemove:             "network",
	ActionNetworkMetadataCleanup:    "network",
	ActionOrchestratorMetadataClean: "orchestrator",
	ActionOrchestratorVMDelete:      "orchestrator",
}

func Parse(value string) (Action, error) {
	action := Action(strings.TrimSpace(value))
	if _, ok := actionScopes[action]; !ok {
		return "", fmt.Errorf("unknown cascade action %q", value)
	}
	return action, nil
}

func ValidateScope(resourceType string, action Action) error {
	expected, ok := actionScopes[action]
	if !ok {
		return fmt.Errorf("unknown cascade action %q", action)
	}
	if strings.TrimSpace(resourceType) != expected {
		return fmt.Errorf("cascade action %q requires resource type %q, got %q",
			action, expected, resourceType)
	}
	return nil
}

func PrimaryAction(resourceType string) (Action, error) {
	switch strings.TrimSpace(resourceType) {
	case "vm":
		return ActionGuestDeleteExact, nil
	case "relay":
		return ActionRelayRemove, nil
	case "nat":
		return ActionNATDisable, nil
	case "network":
		return ActionNetworkRemove, nil
	default:
		return "", fmt.Errorf("unsupported cascade resource type %q", resourceType)
	}
}

func OperationsForResource(resourceType string) ([]Operation, error) {
	switch strings.TrimSpace(resourceType) {
	case "vm":
		return []Operation{
			{ResourceType: "vm", Action: ActionGuestRemove},
			{ResourceType: "vm", Action: ActionGuestReleaseResources},
			{ResourceType: "vm", Action: ActionGuestDeleteExact},
		}, nil
	case "nat":
		return []Operation{
			{ResourceType: "nat", Action: ActionNATDisable},
			{ResourceType: "nat", Action: ActionNATReconcile},
		}, nil
	case "relay":
		return []Operation{
			{ResourceType: "relay", Action: ActionRelayRetire},
			{ResourceType: "relay", Action: ActionRelayRemove},
		}, nil
	case "network":
		return []Operation{
			{ResourceType: "network", Action: ActionNetworkRemove},
			{ResourceType: "network", Action: ActionAdapterMetadataReconcile},
			{ResourceType: "network", Action: ActionAdapterRemove},
			{ResourceType: "network", Action: ActionPrivateSwitchDelete},
			{ResourceType: "network", Action: ActionNetworkMetadataCleanup},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported cascade resource type %q", resourceType)
	}
}

func OrchestratorOperations() []Operation {
	return []Operation{
		{ResourceType: "orchestrator", Action: ActionOrchestratorVMDelete},
		{ResourceType: "orchestrator", Action: ActionOrchestratorMetadataClean},
	}
}

func IsHostAction(action Action) bool {
	switch action {
	case ActionGuestDeleteExact,
		ActionAdapterMetadataReconcile,
		ActionAdapterRemove,
		ActionPrivateSwitchDelete,
		ActionNetworkMetadataCleanup,
		ActionOrchestratorMetadataClean,
		ActionOrchestratorVMDelete:
		return true
	default:
		return false
	}
}
