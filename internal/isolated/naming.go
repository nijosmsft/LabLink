package isolated

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	MaxPhysicalNameLength    = 63
	MaxWindowsNodeNameLength = 15
)

var safePhysicalName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

type OrchestratorPhysicalNames struct {
	HyperVName string
	NodeName   string
}

type NetworkPhysicalNames struct {
	HyperVSwitchName        string
	OrchestratorAdapterName string
}

type VMPhysicalNames struct {
	HyperVName         string
	NodeName           string
	PrivateAdapterName string
}

func OrchestratorNames(id OrchestratorID) (OrchestratorPhysicalNames, error) {
	if err := id.Validate(); err != nil {
		return OrchestratorPhysicalNames{}, err
	}
	hyperVName, err := PhysicalName("isolated-orchestrator", id.String(), MaxPhysicalNameLength)
	if err != nil {
		return OrchestratorPhysicalNames{}, err
	}
	nodeName, err := PhysicalName("orchestrator", id.String(), MaxPhysicalNameLength)
	if err != nil {
		return OrchestratorPhysicalNames{}, err
	}
	return OrchestratorPhysicalNames{HyperVName: hyperVName, NodeName: nodeName}, nil
}

func NetworkNames(id NetworkID) (NetworkPhysicalNames, error) {
	if err := id.Validate(); err != nil {
		return NetworkPhysicalNames{}, err
	}
	switchName, err := PhysicalName("isolated-network", id.String(), MaxPhysicalNameLength)
	if err != nil {
		return NetworkPhysicalNames{}, err
	}
	adapterName, err := PhysicalName("network", id.String(), MaxPhysicalNameLength)
	if err != nil {
		return NetworkPhysicalNames{}, err
	}
	return NetworkPhysicalNames{
		HyperVSwitchName:        switchName,
		OrchestratorAdapterName: adapterName,
	}, nil
}

func VMNames(id VMID) (VMPhysicalNames, error) {
	if err := id.Validate(); err != nil {
		return VMPhysicalNames{}, err
	}
	hyperVName, err := PhysicalName("isolated-vm", id.String(), MaxPhysicalNameLength)
	if err != nil {
		return VMPhysicalNames{}, err
	}
	nodeName, err := PhysicalName("vm", id.String(), MaxWindowsNodeNameLength)
	if err != nil {
		return VMPhysicalNames{}, err
	}
	adapterName, err := PhysicalName("private", id.String(), MaxPhysicalNameLength)
	if err != nil {
		return VMPhysicalNames{}, err
	}
	return VMPhysicalNames{
		HyperVName:         hyperVName,
		NodeName:           nodeName,
		PrivateAdapterName: adapterName,
	}, nil
}

func NormalizeHumanPrefix(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var normalized strings.Builder
	separator := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if separator && normalized.Len() > 0 {
				normalized.WriteByte('-')
			}
			normalized.WriteRune(r)
			separator = false
		default:
			separator = true
		}
	}
	return strings.Trim(normalized.String(), "-")
}

func PhysicalName(humanPrefix, immutableID string, maxLength int) (string, error) {
	normalizedID, err := parseImmutableID("resource", immutableID)
	if err != nil {
		return "", err
	}
	prefix := NormalizeHumanPrefix(humanPrefix)
	if prefix == "" {
		return "", fmt.Errorf("physical name requires a human-readable ASCII prefix")
	}
	if maxLength < ShortIDLength+2 || maxLength > MaxPhysicalNameLength {
		return "", fmt.Errorf(
			"physical name length bound must be between %d and %d",
			ShortIDLength+2,
			MaxPhysicalNameLength,
		)
	}

	suffix := shortImmutableID(normalizedID)
	maxPrefixLength := maxLength - len(suffix) - 1
	if len(prefix) > maxPrefixLength {
		prefix = strings.Trim(prefix[:maxPrefixLength], "-")
	}
	if prefix == "" {
		return "", fmt.Errorf("physical name prefix is empty after applying length bound")
	}
	name := prefix + "-" + suffix
	if len(name) > maxLength || !safePhysicalName.MatchString(name) {
		return "", fmt.Errorf("generated physical name %q is not Windows/Hyper-V safe", name)
	}
	return name, nil
}

func ValidatePhysicalName(value string, maxLength int) error {
	if maxLength < 1 || maxLength > MaxPhysicalNameLength {
		return fmt.Errorf("physical name maximum length must be between 1 and %d", MaxPhysicalNameLength)
	}
	if len(value) == 0 || len(value) > maxLength || !safePhysicalName.MatchString(value) {
		return fmt.Errorf(
			"invalid physical name %q: expected a lowercase ASCII label of at most %d characters",
			value,
			maxLength,
		)
	}
	return nil
}
