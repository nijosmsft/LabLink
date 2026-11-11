package isolated

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const PhysicalHostIdentityVersion = "lablink-physical-host/v1"

var (
	canonicalUUID = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
	)
	canonicalPhysicalHostID = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type PhysicalHostID string

type PhysicalHostIdentity struct {
	MachineGUID string
	SMBIOSUUID  string
	ID          PhysicalHostID
}

type HostReference struct {
	Alias      string
	PhysicalID PhysicalHostID
}

type HostIdentityChangedError struct {
	Alias    string
	Expected PhysicalHostID
	Observed PhysicalHostID
}

func DerivePhysicalHostIdentity(machineGUID, smbiosUUID string) (PhysicalHostIdentity, error) {
	machineGUID, err := normalizeHardwareUUID("MachineGuid", machineGUID)
	if err != nil {
		return PhysicalHostIdentity{}, err
	}
	smbiosUUID, err = normalizeHardwareUUID("SMBIOS UUID", smbiosUUID)
	if err != nil {
		return PhysicalHostIdentity{}, err
	}

	tuple := strings.Join(
		[]string{PhysicalHostIdentityVersion, machineGUID, smbiosUUID},
		"\x00",
	)
	digest := sha256.Sum256([]byte(tuple))
	return PhysicalHostIdentity{
		MachineGUID: machineGUID,
		SMBIOSUUID:  smbiosUUID,
		ID:          PhysicalHostID(hex.EncodeToString(digest[:])),
	}, nil
}

func ParsePhysicalHostID(value string) (PhysicalHostID, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	id := PhysicalHostID(normalized)
	if err := id.Validate(); err != nil {
		return "", err
	}
	return id, nil
}

func (id PhysicalHostID) String() string {
	return string(id)
}

func (id PhysicalHostID) Validate() error {
	if !canonicalPhysicalHostID.MatchString(string(id)) {
		return fmt.Errorf(
			"invalid physical host ID %q: expected a lowercase SHA-256 value",
			id,
		)
	}
	return nil
}

func NormalizeHostAlias(value string) (string, error) {
	alias := strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(alias, "[") && strings.HasSuffix(alias, "]") {
		alias = strings.TrimSpace(alias[1 : len(alias)-1])
	}
	alias = strings.TrimSuffix(alias, ".")
	if alias == "" {
		return "", fmt.Errorf("host alias is required")
	}
	if strings.ContainsAny(alias, "\x00\r\n\t") {
		return "", fmt.Errorf("host alias contains control characters")
	}
	if ip := net.ParseIP(alias); ip != nil {
		return ip.String(), nil
	}
	return alias, nil
}

func NewHostReference(alias string, physicalID PhysicalHostID) (HostReference, error) {
	normalizedAlias, err := NormalizeHostAlias(alias)
	if err != nil {
		return HostReference{}, err
	}
	if err := physicalID.Validate(); err != nil {
		return HostReference{}, err
	}
	return HostReference{Alias: normalizedAlias, PhysicalID: physicalID}, nil
}

func (r HostReference) Validate() error {
	if _, err := NormalizeHostAlias(r.Alias); err != nil {
		return err
	}
	return r.PhysicalID.Validate()
}

func (r HostReference) CanonicalKey() string {
	if r.PhysicalID.Validate() != nil {
		return ""
	}
	return r.PhysicalID.String()
}

func (r HostReference) SamePhysicalHost(other HostReference) bool {
	return r.PhysicalID.Validate() == nil &&
		other.PhysicalID.Validate() == nil &&
		r.PhysicalID == other.PhysicalID
}

func (r HostReference) VerifyObserved(observed PhysicalHostID) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := observed.Validate(); err != nil {
		return err
	}
	if r.PhysicalID != observed {
		return &HostIdentityChangedError{
			Alias:    r.Alias,
			Expected: r.PhysicalID,
			Observed: observed,
		}
	}
	return nil
}

func (e *HostIdentityChangedError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf(
		"HOST_IDENTITY_CHANGED: alias %q was recorded for physical host %s but now resolves to %s; explicit operator reconciliation is required",
		e.Alias,
		e.Expected,
		e.Observed,
	)
}

func normalizeHardwareUUID(field, value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
		value = value[1 : len(value)-1]
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if !canonicalUUID.MatchString(value) {
		return "", fmt.Errorf("%s is missing, a placeholder, or not a canonical UUID", field)
	}
	compact := strings.ReplaceAll(value, "-", "")
	if strings.Trim(compact, "0") == "" || strings.Trim(compact, "f") == "" ||
		isKnownHardwareUUIDPlaceholder(value) {
		return "", fmt.Errorf("%s is a placeholder UUID", field)
	}
	return value, nil
}

func isKnownHardwareUUIDPlaceholder(value string) bool {
	switch value {
	case "03000200-0400-0500-0006-000700080009",
		"00020003-0004-0005-0006-000700080009":
		return true
	default:
		return false
	}
}
