package isolated

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const ShortIDLength = 12

var canonicalRandomUUID = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

type OrchestratorID string
type NetworkID string
type VMID string
type RelayID string
type OperationID string

func NewOrchestratorID() (OrchestratorID, error) {
	value, err := newImmutableID()
	return OrchestratorID(value), err
}

func NewNetworkID() (NetworkID, error) {
	value, err := newImmutableID()
	return NetworkID(value), err
}

func NewVMID() (VMID, error) {
	value, err := newImmutableID()
	return VMID(value), err
}

func NewRelayID() (RelayID, error) {
	value, err := newImmutableID()
	return RelayID(value), err
}

func NewOperationID() (OperationID, error) {
	value, err := newImmutableID()
	return OperationID(value), err
}

func ParseOrchestratorID(value string) (OrchestratorID, error) {
	normalized, err := parseImmutableID("orchestrator", value)
	return OrchestratorID(normalized), err
}

func ParseNetworkID(value string) (NetworkID, error) {
	normalized, err := parseImmutableID("network", value)
	return NetworkID(normalized), err
}

func ParseVMID(value string) (VMID, error) {
	normalized, err := parseImmutableID("VM", value)
	return VMID(normalized), err
}

func ParseRelayID(value string) (RelayID, error) {
	normalized, err := parseImmutableID("relay", value)
	return RelayID(normalized), err
}

func ParseOperationID(value string) (OperationID, error) {
	normalized, err := parseImmutableID("operation", value)
	return OperationID(normalized), err
}

func (id OrchestratorID) String() string { return string(id) }
func (id NetworkID) String() string      { return string(id) }
func (id VMID) String() string           { return string(id) }
func (id RelayID) String() string        { return string(id) }
func (id OperationID) String() string    { return string(id) }

func (id OrchestratorID) Validate() error {
	return validateImmutableID("orchestrator", string(id))
}

func (id NetworkID) Validate() error {
	return validateImmutableID("network", string(id))
}

func (id VMID) Validate() error {
	return validateImmutableID("VM", string(id))
}

func (id RelayID) Validate() error {
	return validateImmutableID("relay", string(id))
}

func (id OperationID) Validate() error {
	return validateImmutableID("operation", string(id))
}

func (id OrchestratorID) Short() string { return shortImmutableID(string(id)) }
func (id NetworkID) Short() string      { return shortImmutableID(string(id)) }
func (id VMID) Short() string           { return shortImmutableID(string(id)) }
func (id RelayID) Short() string        { return shortImmutableID(string(id)) }
func (id OperationID) Short() string    { return shortImmutableID(string(id)) }

func newImmutableID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate cryptographically random UUID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80

	compact := hex.EncodeToString(value[:])
	return compact[0:8] + "-" +
		compact[8:12] + "-" +
		compact[12:16] + "-" +
		compact[16:20] + "-" +
		compact[20:32], nil
}

func parseImmutableID(kind, value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if err := validateImmutableID(kind, normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

func validateImmutableID(kind, value string) error {
	if !canonicalRandomUUID.MatchString(value) {
		return fmt.Errorf(
			"invalid %s ID %q: expected a canonical lowercase random UUID",
			kind,
			value,
		)
	}
	return nil
}

func shortImmutableID(value string) string {
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) < ShortIDLength {
		return ""
	}
	return compact[:ShortIDLength]
}
