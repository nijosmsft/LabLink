package appliance

import (
	"context"
	"crypto/sha256"
	"database/sql"
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

type NATEngineOptions struct {
	Store         *Store
	Applier       *ApplyManager
	Conntrack     ConntrackInspector
	MainInterface string
	PollInterval  time.Duration
	Now           func() time.Time
	OnPollError   func(error)
}

type NATEngine struct {
	store         *Store
	applier       *ApplyManager
	conntrack     ConntrackInspector
	mainInterface string
	pollInterval  time.Duration
	now           func() time.Time
	onPollError   func(error)
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
		onPollError:   options.OnPollError,
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
	failed := false
	for {
		if err := e.PollOnce(ctx); err != nil {
			failed = true
			if e.onPollError != nil {
				e.onPollError(err)
			}
		} else if failed {
			failed = false
			if e.onPollError != nil {
				e.onPollError(nil)
			}
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
		if err := e.completeDrain(ctx, snapshot, network, guest, nat); err != nil {
			pollErrors = append(pollErrors, err)
		}
	}
	return errors.Join(pollErrors...)
}

func (e *NATEngine) completeDrain(
	ctx context.Context,
	snapshot DesiredSnapshot,
	network Network,
	guest Guest,
	nat NATState,
) error {
	return e.applier.completeNATDrain(ctx, natDrainCompletion{
		PhysicalHostID:   snapshot.Authority.PhysicalHostID,
		ParentGeneration: snapshot.Authority.ParentGeneration,
		Network:          network,
		Guest:            guest,
		NAT:              nat,
	})
}

func drainCompletionHeader(
	network Network,
	guest Guest,
	nat NATState,
) MutationHeader {
	generation := nat.DesiredGeneration + 1
	identity := fmt.Sprintf("%s\x00%d\x00%d\x00%d\x00%s\x00%d\x00%d",
		nat.VMID, nat.ConntrackMark, nat.DesiredGeneration, generation,
		network.ID, network.DesiredGeneration, guest.DesiredGeneration)
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
		HostFence:                0,
		ExpectedParentGeneration: guest.DesiredGeneration,
	}
}

type natDrainCompletion struct {
	PhysicalHostID   string
	ParentGeneration uint64
	Network          Network
	Guest            Guest
	NAT              NATState
}

func (s *Store) stageNATDrainCompletionLocked(
	ctx context.Context,
	completion natDrainCompletion,
) (StageResult, error) {
	header := drainCompletionHeader(
		completion.Network, completion.Guest, completion.NAT)
	return s.stageLocked(ctx, header, "nat", true,
		func(ctx context.Context, tx *sql.Tx, header MutationHeader) (Authority, error) {
			authority, err := validateSystemAuthority(ctx, tx)
			if err != nil {
				return Authority{}, err
			}
			if authority.PhysicalHostID != completion.PhysicalHostID ||
				authority.ParentGeneration != completion.ParentGeneration {
				return Authority{}, storeError(CodeFenceRejected,
					"authority changed before NAT drain completion")
			}
			var (
				state                              string
				mark                               int64
				desired, applied, observed, parent uint64
				drainStarted                       sql.NullInt64
			)
			err = tx.QueryRowContext(ctx, `
				SELECT state, conntrack_mark, desired_generation,
					applied_generation, observed_generation, parent_generation,
					drain_started_unix
				FROM nat_state WHERE vm_id = ?
			`, completion.NAT.VMID).Scan(&state, &mark, &desired, &applied,
				&observed, &parent, &drainStarted)
			if err != nil {
				return Authority{}, err
			}
			if state != "draining" || !drainStarted.Valid ||
				mark != completion.NAT.ConntrackMark ||
				desired != completion.NAT.DesiredGeneration ||
				desired != applied || desired != observed ||
				parent != completion.Guest.DesiredGeneration {
				return Authority{}, storeError(CodeGenerationConflict,
					"NAT drain state changed before completion")
			}
			if err := validateDrainGuestAndNetwork(
				ctx, tx, completion.Network, completion.Guest); err != nil {
				return Authority{}, err
			}
			if err := requireReservation(ctx, tx, "conntrack_mark", completion.NAT.VMID, `
				AND conntrack_mark = ?
			`, completion.NAT.ConntrackMark); err != nil {
				if fallbackErr := requireReservation(ctx, tx, "guest", completion.NAT.VMID, `
					AND conntrack_mark = ?
				`, completion.NAT.ConntrackMark); fallbackErr != nil {
					return Authority{}, fallbackErr
				}
			}
			return authority, nil
		},
		func(ctx context.Context, tx *sql.Tx) error {
			result, err := tx.ExecContext(ctx, `
				UPDATE nat_state
				SET state='disabled', desired_generation=?, parent_generation=?,
					drain_started_unix=NULL, last_error=NULL
				WHERE vm_id=? AND state='draining' AND conntrack_mark=?
					AND desired_generation=? AND applied_generation=?
					AND observed_generation=? AND parent_generation=?
					AND drain_started_unix IS NOT NULL
			`, header.NewGeneration, completion.Guest.DesiredGeneration,
				completion.NAT.VMID, completion.NAT.ConntrackMark,
				completion.NAT.DesiredGeneration, completion.NAT.DesiredGeneration,
				completion.NAT.DesiredGeneration, completion.Guest.DesiredGeneration)
			if err != nil {
				return err
			}
			if changed, _ := result.RowsAffected(); changed != 1 {
				return storeError(CodeGenerationConflict,
					"NAT drain state changed while completing")
			}
			return nil
		})
}

func validateDrainGuestAndNetwork(
	ctx context.Context,
	tx *sql.Tx,
	network Network,
	guest Guest,
) error {
	var (
		guestNetwork, guestIPv4, guestState                    string
		guestDesired, guestApplied, guestObserved, guestParent uint64
		guestRetired                                           sql.NullInt64
	)
	err := tx.QueryRowContext(ctx, `
		SELECT network_id, ipv4, state, desired_generation, applied_generation,
			observed_generation, parent_generation, retired_at_unix
		FROM guests WHERE id = ?
	`, guest.ID).Scan(&guestNetwork, &guestIPv4, &guestState, &guestDesired,
		&guestApplied, &guestObserved, &guestParent, &guestRetired)
	if err != nil {
		return err
	}
	if guestRetired.Valid || guestNetwork != network.ID || guestIPv4 != guest.IPv4 ||
		guestState != guest.State || guestDesired != guest.DesiredGeneration ||
		guestDesired != guestApplied || guestDesired != guestObserved {
		return storeError(CodeGenerationConflict,
			"guest changed before NAT drain completion")
	}
	var (
		interfaceName, networkState                     string
		networkDesired, networkApplied, networkObserved uint64
		networkRetired                                  sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `
		SELECT interface_name, state, desired_generation, applied_generation,
			observed_generation, retired_at_unix
		FROM networks WHERE id = ?
	`, network.ID).Scan(&interfaceName, &networkState, &networkDesired,
		&networkApplied, &networkObserved, &networkRetired)
	if err != nil {
		return err
	}
	if networkRetired.Valid || interfaceName != network.InterfaceName ||
		networkState != network.State || networkDesired != network.DesiredGeneration ||
		networkDesired != networkApplied || networkDesired != networkObserved ||
		guestParent != networkDesired {
		return storeError(CodeGenerationConflict,
			"network changed before NAT drain completion")
	}
	return nil
}

func validateNATSystemIntent(
	ctx context.Context,
	tx *sql.Tx,
	intent Intent,
) error {
	if !intent.SystemTransition || intent.ResourceKind != "nat" ||
		intent.ResourceID == "" || intent.ParentResourceID != intent.ResourceID ||
		intent.DesiredGeneration == 0 ||
		!strings.HasPrefix(intent.MutationID, "nat-drain-complete-") {
		return storeError(CodeInvalidArgument,
			"invalid internal NAT drain completion identity")
	}
	var (
		nat          NATState
		drainStarted sql.NullInt64
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT vm_id, state, conntrack_mark, desired_generation,
			applied_generation, observed_generation, parent_generation,
			drain_started_unix, COALESCE(last_error, '')
		FROM nat_state WHERE vm_id = ?
	`, intent.ResourceID).Scan(&nat.VMID, &nat.State, &nat.ConntrackMark,
		&nat.DesiredGeneration, &nat.AppliedGeneration, &nat.ObservedGeneration,
		&nat.ParentGeneration, &drainStarted, &nat.LastError); err != nil {
		return err
	}
	if drainStarted.Valid || nat.State != "disabled" ||
		nat.DesiredGeneration != intent.DesiredGeneration ||
		nat.AppliedGeneration+1 != nat.DesiredGeneration ||
		nat.ObservedGeneration != nat.AppliedGeneration ||
		nat.ParentGeneration != intent.ParentGeneration {
		return storeError(CodeGenerationConflict,
			"internal NAT drain completion state is not exact")
	}
	var guest Guest
	var guestRetired sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT id, network_id, ipv4, mac, desired_generation,
			applied_generation, observed_generation, parent_generation,
			incarnation, state, COALESCE(last_error, ''), retired_at_unix
		FROM guests WHERE id = ?
	`, nat.VMID).Scan(&guest.ID, &guest.NetworkID, &guest.IPv4, &guest.MAC,
		&guest.DesiredGeneration, &guest.AppliedGeneration,
		&guest.ObservedGeneration, &guest.ParentGeneration,
		&guest.Incarnation, &guest.State, &guest.LastError, &guestRetired); err != nil {
		return err
	}
	guest.RetiredAtUnix = nullInt64Ptr(guestRetired)
	var network Network
	var networkRetired sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT id, cidr, gateway_ipv4, nic_mac, COALESCE(interface_name, ''),
			dns_servers_json, desired_generation, applied_generation,
			observed_generation, parent_generation, incarnation, state,
			COALESCE(last_error, ''), retired_at_unix
		FROM networks WHERE id = ?
	`, guest.NetworkID).Scan(&network.ID, &network.CIDR, &network.GatewayIPv4,
		&network.NICMAC, &network.InterfaceName, &network.DNSServersJSON,
		&network.DesiredGeneration, &network.AppliedGeneration,
		&network.ObservedGeneration, &network.ParentGeneration,
		&network.Incarnation, &network.State, &network.LastError,
		&networkRetired); err != nil {
		return err
	}
	network.RetiredAtUnix = nullInt64Ptr(networkRetired)
	if err := validateDrainGuestAndNetwork(ctx, tx, network, guest); err != nil {
		return err
	}
	oldNAT := nat
	oldNAT.State = "draining"
	oldNAT.DesiredGeneration--
	oldNAT.AppliedGeneration = oldNAT.DesiredGeneration
	oldNAT.ObservedGeneration = oldNAT.DesiredGeneration
	expected := drainCompletionHeader(network, guest, oldNAT)
	if intent.MutationID != expected.MutationID ||
		intent.ParentOperationID != expected.ParentOperationID ||
		intent.SemanticHash != expected.SemanticHash ||
		intent.Fence != expected.HostFence ||
		intent.ParentGeneration != expected.ExpectedParentGeneration {
		return storeError(CodeResumeMismatch,
			"internal NAT drain completion identity changed")
	}
	return nil
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
