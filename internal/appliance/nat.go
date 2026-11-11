package appliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const defaultNATPollInterval = 2 * time.Second

type ConntrackTuple struct {
	Source          netip.Addr
	Destination     netip.Addr
	SourcePort      uint16
	DestinationPort uint16
}

type ConntrackEntry struct {
	Protocol string
	State    string
	Original ConntrackTuple
	Reply    ConntrackTuple
	Mark     uint32
}

type ConntrackFilter struct {
	GuestIPv4        netip.Addr
	PrivateInterface string
	MainInterface    string
	ConntrackMark    uint32
}

type ConntrackParser interface {
	Parse(string) ([]ConntrackEntry, error)
}

type ConntrackInspector interface {
	Count(context.Context, ConntrackFilter) (int, error)
}

type IntentApplier interface {
	ApplyIntent(context.Context, string) (AppliedOperation, error)
}

type NATEngineOptions struct {
	Store         *Store
	Applier       IntentApplier
	Conntrack     ConntrackInspector
	MainInterface string
	PollInterval  time.Duration
	Now           func() time.Time
}

type NATEngine struct {
	store         *Store
	applier       IntentApplier
	conntrack     ConntrackInspector
	mainInterface string
	pollInterval  time.Duration
	now           func() time.Time
}

func NewNATEngine(options NATEngineOptions) (*NATEngine, error) {
	if options.Store == nil || options.Applier == nil || options.Conntrack == nil {
		return nil, storeError(CodeInvalidArgument,
			"NAT store, intent applier, and conntrack inspector are required")
	}
	if err := validateInterfaceName(options.MainInterface); err != nil {
		return nil, storeError(CodeInvalidArgument, "NAT main interface: %v", err)
	}
	if options.PollInterval < 0 {
		return nil, storeError(CodeInvalidArgument, "NAT poll interval cannot be negative")
	}
	if options.PollInterval == 0 {
		options.PollInterval = defaultNATPollInterval
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &NATEngine{
		store:         options.Store,
		applier:       options.Applier,
		conntrack:     options.Conntrack,
		mainInterface: options.MainInterface,
		pollInterval:  options.PollInterval,
		now:           options.Now,
	}, nil
}

// SetEnabled stages and applies one atomic NAT mutation. A disable request for
// an enabled VM is persisted as draining so the compiled policy rejects new
// flows while retaining the established-flow mark and masquerade rules.
func (e *NATEngine) SetEnabled(
	ctx context.Context,
	header MutationHeader,
	conntrackMark int64,
	enabled bool,
) (NATState, error) {
	state := "disabled"
	if enabled {
		state = "enabled"
	}
	stage, err := e.store.StageNAT(ctx, header, NATState{
		VMID:          header.ResourceID,
		State:         state,
		ConntrackMark: conntrackMark,
	})
	if err != nil {
		return NATState{}, err
	}
	if !stage.Replay || stage.Intent.MutationID != "" {
		if _, err := e.applier.ApplyIntent(ctx, header.MutationID); err != nil {
			return NATState{}, err
		}
	}
	nat, found, err := e.store.NAT(ctx, header.ResourceID)
	if err != nil {
		return NATState{}, err
	}
	if !found {
		return NATState{}, storeError(CodeNotFound,
			"NAT state for VM %q disappeared after apply", header.ResourceID)
	}
	return nat, nil
}

// ApplyStaged applies a NAT intent staged by an existing store/API caller.
func (e *NATEngine) ApplyStaged(
	ctx context.Context,
	mutationID string,
) (AppliedOperation, error) {
	return e.applier.ApplyIntent(ctx, mutationID)
}

// Monitor runs until the context is cancelled. Draining has no deadline:
// transition to disabled occurs only after the matching conntrack count is zero.
func (e *NATEngine) Monitor(ctx context.Context) error {
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()
	for {
		if err := e.PollOnce(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (e *NATEngine) PollOnce(ctx context.Context) error {
	snapshot, err := e.store.Snapshot(ctx)
	if err != nil {
		return err
	}
	guests := make(map[string]Guest, len(snapshot.Guests))
	for _, guest := range snapshot.Guests {
		if guest.RetiredAtUnix == nil && guest.State != "retired" {
			guests[guest.ID] = guest
		}
	}
	networks := make(map[string]Network, len(snapshot.Networks))
	for _, network := range snapshot.Networks {
		if network.RetiredAtUnix == nil && network.State != "retired" {
			networks[network.ID] = network
		}
	}

	var pollErrors []error
	for _, nat := range snapshot.NAT {
		if nat.State != "draining" ||
			nat.DesiredGeneration != nat.AppliedGeneration ||
			nat.DesiredGeneration != nat.ObservedGeneration {
			continue
		}
		guest, ok := guests[nat.VMID]
		if !ok {
			pollErrors = append(pollErrors,
				fmt.Errorf("appliance: draining NAT VM %q is not an active guest", nat.VMID))
			continue
		}
		network, ok := networks[guest.NetworkID]
		if !ok {
			pollErrors = append(pollErrors,
				fmt.Errorf("appliance: draining NAT VM %q network %q is not active",
					nat.VMID, guest.NetworkID))
			continue
		}
		address, parseErr := netip.ParseAddr(guest.IPv4)
		if parseErr != nil || !address.Is4() {
			pollErrors = append(pollErrors,
				fmt.Errorf("appliance: draining NAT VM %q has invalid IPv4 %q",
					nat.VMID, guest.IPv4))
			continue
		}
		if nat.ConntrackMark <= 0 || nat.ConntrackMark > int64(^uint32(0)) {
			pollErrors = append(pollErrors,
				fmt.Errorf("appliance: draining NAT VM %q has invalid conntrack mark %d",
					nat.VMID, nat.ConntrackMark))
			continue
		}
		count, countErr := e.conntrack.Count(ctx, ConntrackFilter{
			GuestIPv4:        address,
			PrivateInterface: network.InterfaceName,
			MainInterface:    e.mainInterface,
			ConntrackMark:    uint32(nat.ConntrackMark),
		})
		if countErr != nil {
			pollErrors = append(pollErrors,
				fmt.Errorf("appliance: inspect conntrack for VM %q: %w", nat.VMID, countErr))
			continue
		}
		if count != 0 {
			continue
		}
		if err := e.completeDrain(ctx, snapshot, guest, nat); err != nil {
			pollErrors = append(pollErrors, err)
		}
	}
	return errors.Join(pollErrors...)
}

func (e *NATEngine) completeDrain(
	ctx context.Context,
	snapshot DesiredSnapshot,
	guest Guest,
	nat NATState,
) error {
	header := drainCompletionHeader(snapshot.Authority, guest, nat, e.now())
	stage, err := e.store.stageNAT(ctx, header, NATState{
		VMID:          nat.VMID,
		State:         "disabled",
		ConntrackMark: nat.ConntrackMark,
	}, true)
	if err != nil {
		return err
	}
	if stage.Replay && stage.Intent.MutationID == "" {
		return nil
	}
	_, err = e.applier.ApplyIntent(ctx, header.MutationID)
	return err
}

func drainCompletionHeader(
	authority Authority,
	guest Guest,
	nat NATState,
	now time.Time,
) MutationHeader {
	generation := nat.DesiredGeneration + 1
	identity := fmt.Sprintf("%s\x00%d\x00%d\x00%d",
		nat.VMID, nat.ConntrackMark, generation, now.UnixNano())
	sum := sha256.Sum256([]byte("lablink-nat-drain-complete-v1\x00" + identity))
	hash := hex.EncodeToString(sum[:])
	mutationID := "nat-drain-complete-" + hash[:24]
	return MutationHeader{
		ParentOperationID:        mutationID,
		MutationID:               mutationID,
		SemanticHash:             hash,
		ResourceID:               nat.VMID,
		ParentResourceID:         nat.VMID,
		ExpectedGeneration:       nat.DesiredGeneration,
		NewGeneration:            generation,
		HostFence:                authority.Fence,
		ExpectedParentGeneration: guest.DesiredGeneration,
	}
}

func ConntrackEntryMatches(entry ConntrackEntry, filter ConntrackFilter) bool {
	if !filter.GuestIPv4.Is4() || filter.ConntrackMark == 0 ||
		entry.Mark != filter.ConntrackMark {
		return false
	}
	// Forwarded guest flows always retain the original guest source tuple.
	// The local relay connection originates from the appliance gateway and is
	// therefore excluded even though its target is guest TCP/9091.
	return entry.Original.Source.Unmap() == filter.GuestIPv4.Unmap()
}

func validateConntrackFilter(filter ConntrackFilter) error {
	if !filter.GuestIPv4.Is4() || filter.GuestIPv4.IsUnspecified() ||
		filter.GuestIPv4.IsLoopback() || filter.GuestIPv4.IsMulticast() {
		return fmt.Errorf("invalid managed guest IPv4 %q", filter.GuestIPv4)
	}
	if filter.ConntrackMark == 0 {
		return fmt.Errorf("conntrack mark must be non-zero")
	}
	if err := validateInterfaceName(strings.TrimSpace(filter.PrivateInterface)); err != nil {
		return fmt.Errorf("private interface: %w", err)
	}
	if err := validateInterfaceName(strings.TrimSpace(filter.MainInterface)); err != nil {
		return fmt.Errorf("main interface: %w", err)
	}
	if filter.PrivateInterface == filter.MainInterface {
		return fmt.Errorf("private and main interfaces must differ")
	}
	return nil
}

func validateInterfaceName(value string) error {
	if value == "" || len(value) > 15 {
		return fmt.Errorf("invalid interface name %q", value)
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '-' || character == '.') {
			return fmt.Errorf("invalid interface name %q", value)
		}
	}
	return nil
}
