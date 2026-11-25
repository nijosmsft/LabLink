//go:build linux

package appliance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nijosmsft/lablink/internal/flock"
)

const managementDir = "/var/lib/lablink-agent/appliance/management-ip"
const managementPending = managementDir + "/pending.json"
const managementRollbackUnit = "lablink-management-ip-rollback"
const managementTimeoutUnit = "lablink-management-ip-timeout"

type managementPendingPin struct {
	Token  string
	Before managementObservation
}

func managementCommand(ctx context.Context, name string, args ...string) (string, error) {
	result, err := (OSCommandExecutor{}).Run(ctx, name, args...)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", commandFailure(name, result)
	}
	return result.Stdout, nil
}

func captureManagementIP(ctx context.Context, iface, expected string, privateMACs []string, fullStatic bool) (managementObservation, string, error) {
	return (managementIPCapture{
		executor: OSCommandExecutor{}, readFile: os.ReadFile, glob: filepath.Glob,
	}).capture(ctx, iface, expected, privateMACs, fullStatic)
}

func readManagementPending() (*managementPendingPin, error) {
	data, err := os.ReadFile(managementPending)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pending managementPendingPin
	if err := json.Unmarshal(data, &pending); err != nil {
		return nil, err
	}
	if pending.Token == "" || len(pending.Before.Main.IPv4Addresses) != 1 ||
		validateInterfaceName(pending.Before.Main.InterfaceName) != nil ||
		strings.HasPrefix(pending.Before.Main.InterfaceName, "-") {
		return nil, fmt.Errorf("invalid pending management pin; manual recovery required")
	}
	return &pending, nil
}

func removeManagementFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func verifyManagementPin(ctx context.Context, pending *managementPendingPin) error {
	before := pending.Before
	after, _, err := captureManagementIP(ctx, before.Main.InterfaceName, before.Main.IPv4Addresses[0].Prefix.Addr().String(), nil, true)
	if err != nil {
		return err
	}
	if after.Main.AddressSource != MainAddressStatic || after.Main.MAC != before.Main.MAC ||
		after.Main.IPv4Addresses[0].Prefix != before.Main.IPv4Addresses[0].Prefix ||
		after.MTU != before.MTU ||
		!sameStrings(routeStrings(before.Main.DefaultRoutes), routeStrings(after.Main.DefaultRoutes)) ||
		!sameStrings(routeStrings(before.Main.NonDefaultRoutes), routeStrings(after.Main.NonDefaultRoutes)) ||
		!sameManagementValues(before.DNS, after.DNS) || !sameManagementValues(before.Domains, after.Domains) {
		return fmt.Errorf("management address, routes, MTU or DNS changed during pinning")
	}
	status, err := managementCommand(ctx, "networkctl", "status", "--no-pager", "--full", before.Main.InterfaceName)
	if err != nil || !strings.Contains(status, managementUnit) {
		return fmt.Errorf("management NIC did not select the persistent LabLink unit: %v", err)
	}
	return nil
}

// PinManagementIPv4 is called only by the authenticated appliance RPC.
// The original networkd/Netplan files are never edited.
func PinManagementIPv4(ctx context.Context, iface, expected, confirm string, privateMACs []string) (string, string, error) {
	if err := os.MkdirAll(managementDir, 0o700); err != nil {
		return "", "", err
	}
	lock, err := flock.Lock(managementDir + "/lock")
	if err != nil {
		return "", "", err
	}
	defer lock.Close()
	pending, err := readManagementPending()
	if err != nil {
		return "", "", err
	}
	if confirm != "" {
		if pending == nil || pending.Token != confirm || pending.Before.Main.InterfaceName != iface ||
			pending.Before.Main.IPv4Addresses[0].Prefix.Addr().String() != expected {
			return "", "", fmt.Errorf("management pin confirmation does not match a pending operation")
		}
		if err := verifyManagementPin(ctx, pending); err != nil {
			return "", "", err
		}
		if err := removeManagementFile(managementPending); err != nil {
			return "", "", err
		}
		_, _ = managementCommand(ctx, "systemctl", "stop", managementTimeoutUnit+".timer")
		return "", "management IPv4 pinned; DHCP collision and host subnet renumbering remain possible", nil
	}
	if pending != nil {
		return "", "", fmt.Errorf("management IPv4 pin is awaiting confirmation or rollback")
	}
	observed, original, err := captureManagementIP(ctx, iface, expected, privateMACs, false)
	if err != nil {
		return "", "", err
	}
	if observed.Main.AddressSource == MainAddressStatic {
		return "", "management IPv4 already static; unchanged", nil
	}
	candidate, err := renderManagementIP(original, observed)
	if err != nil {
		return "", "", err
	}
	if _, err := os.Lstat(managementUnit); !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("refusing to overwrite an existing management pin unit")
	}
	executable, err := os.Executable()
	if err != nil || strings.ContainsAny(executable, "\r\n%") {
		return "", "", fmt.Errorf("unsupported rollback executable path")
	}
	unit := "[Unit]\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target\nWants=network-pre.target\n" +
		"[Service]\nType=oneshot\nExecStart=" + strconv.Quote(executable) + " --rollback-management-ip\n" +
		"[Install]\nWantedBy=network-pre.target\n"
	fs := OSFileSystem{}
	if err := fs.WriteFileAtomic("/etc/systemd/system/"+managementRollbackUnit+".service", []byte(unit), 0o644); err != nil {
		return "", "", err
	}
	for _, command := range [][]string{{"daemon-reload"}, {"enable", managementRollbackUnit + ".service"}} {
		if _, err := managementCommand(ctx, "systemctl", command...); err != nil {
			return "", "", err
		}
	}
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", "", err
	}
	pending = &managementPendingPin{Token: hex.EncodeToString(random), Before: observed}
	data, err := json.Marshal(pending)
	if err != nil {
		return "", "", err
	}
	if err := fs.WriteFileAtomic(managementPending, data, 0o600); err != nil {
		return "", "", err
	}
	// Arm the independent process before writing or applying the candidate.
	if _, err := managementCommand(ctx, "systemd-run", "--quiet", "--collect", "--unit="+managementTimeoutUnit,
		"--on-active=60s", "--timer-property=AccuracySec=1s", executable, "--rollback-management-ip"); err != nil {
		_ = removeManagementFile(managementPending)
		return "", "", fmt.Errorf("cannot arm management DHCP rollback: %w", err)
	}
	err = applyManagementIP(
		func() error { return fs.WriteFileAtomic(managementUnit, []byte(candidate), 0o644) },
		func() error {
			if _, err := managementCommand(ctx, "networkctl", "reload"); err != nil {
				return err
			}
			_, err := managementCommand(ctx, "networkctl", "reconfigure", iface)
			return err
		},
		func() error {
			verifyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			for {
				err := verifyManagementPin(verifyCtx, pending)
				if err == nil {
					return nil
				}
				select {
				case <-verifyCtx.Done():
					return fmt.Errorf("management pin did not converge: %w", err)
				case <-time.After(200 * time.Millisecond):
				}
			}
		},
		func() error {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			return rollbackManagementIPLocked(rollbackCtx, pending)
		})
	if err != nil {
		return "", "", err
	}
	return pending.Token, "management IPv4 applied; confirmation required within 60 seconds", nil
}

func rollbackManagementIPLocked(ctx context.Context, pending *managementPendingPin) error {
	if err := removeManagementFile(managementUnit); err != nil {
		return err
	}
	active, err := (OSCommandExecutor{}).Run(ctx, "systemctl", "is-active", "--quiet", "systemd-networkd.service")
	if err != nil {
		return err
	}
	if active.ExitCode == 0 {
		if _, err := managementCommand(ctx, "networkctl", "reload"); err != nil {
			return err
		}
		if _, err := managementCommand(ctx, "networkctl", "reconfigure", pending.Before.Main.InterfaceName); err != nil {
			return err
		}
	}
	return removeManagementFile(managementPending)
}

// RollbackManagementIPv4 is also run before network-pre.target after a reboot.
func RollbackManagementIPv4(ctx context.Context) error {
	if _, err := os.Stat(managementDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	lock, err := flock.Lock(managementDir + "/lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	pending, err := readManagementPending()
	if err != nil || pending == nil {
		return err
	}
	return rollbackManagementIPLocked(ctx, pending)
}
