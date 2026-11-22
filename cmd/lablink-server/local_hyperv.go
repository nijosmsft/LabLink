package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/mcptools"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

func configureLocalHyperV(args []string, remove bool) error {
	flags := flag.NewFlagSet("register-local-hyperv", flag.ContinueOnError)
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configDir := flags.String("home", filepath.Join(home, ".lablink"), "operator LabLink home")
	name := flags.String("name", "local-hyperv", "registered node and TLS name")
	address := flags.String("address", "127.0.0.1:19091", "restricted service endpoint")
	vmRoot := flags.String("vm-root", "", "installed VM storage root")
	imageRoot := flags.String("image-root", "", "installed image cache root")
	mainSwitch := flags.String("vswitch", "", "approved guest switch")
	base := flags.String("windows-base", "", "approved Windows base image")
	previousBase := flags.String("previous-windows-base", "", "previous primary base to migrate into approved storage")
	credential := flags.String("vm-credential", "local-vm-admin", "existing operator credential profile for VM passwords")
	if err := flags.Parse(args); err != nil {
		return err
	}
	reg := registry.Load(filepath.Join(*configDir, "nodes.json"))
	if existing, found := reg.GetNode(*name); found && existing.Labels["lablink.local_hyperv"] != "true" {
		return fmt.Errorf("node name %q is already used by another endpoint", *name)
	}
	if remove {
		if _, found := reg.GetNode(*name); !found {
			return nil
		}
		return reg.RemoveNode(*name)
	}
	pki := filepath.Join(*configDir, "pki")
	token, err := os.ReadFile(filepath.Join(*configDir, "agent.token"))
	if err != nil {
		return err
	}
	transport, err := security.ResolveClientTransport("mtls", false,
		filepath.Join(pki, "ca-bundle", "ca.crt"),
		filepath.Join(pki, "clients", "default", "client.crt"),
		filepath.Join(pki, "clients", "default", "client.key"), "")
	if err != nil {
		return err
	}
	pool := agentclient.NewPool(strings.TrimSpace(string(token)), transport)
	defer pool.Close()
	client, err := pool.GetClient(*address, *name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	info, err := client.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		return err
	}
	restricted := false
	for _, capability := range info.Capabilities {
		restricted = restricted || capability == mcptools.LocalHyperVCapability
	}
	if !restricted {
		return fmt.Errorf("local endpoint did not advertise the restricted Hyper-V capability")
	}
	if err := reg.SetNode(&registry.Node{
		Name: *name, Address: *address, TLSServerName: *name, TransportMode: "mtls",
		Role: "hyperv-only", OS: info.Os, Arch: info.Arch,
		Labels: map[string]string{"lablink.local_hyperv": "true"},
	}); err != nil {
		return err
	}
	if *vmRoot != "" && *imageRoot != "" && *mainSwitch != "" {
		store := vmconfig.Load(filepath.Join(*configDir, "vm-defaults.json"))
		config, err := store.List()
		if err != nil {
			return err
		}
		for _, profileName := range []string{"local-windows", "local-linux-builder", "local-ubuntu"} {
			if existing, found := config.Profiles[profileName]; found && !strings.EqualFold(existing.Target, *name) {
				return fmt.Errorf("template %q already belongs to another target; rename it before local setup", profileName)
			}
		}
		save := func(profileName string, profile vmconfig.Profile) error {
			if existing, found := config.Profiles[profileName]; found {
				// Installation may move the approved base into protected storage;
				// retain the user's other guest settings on upgrades.
				if profile.BaseVHD == "" || !strings.EqualFold(existing.BaseVHD, *previousBase) || existing.BaseVHD == profile.BaseVHD {
					return nil
				}
				existing.BaseVHD = profile.BaseVHD
				profile = existing
			}
			return store.Set(profileName, profile, false)
		}
		enroll := true
		localWindows := vmconfig.Profile{
			Target: *name, GuestOS: "windows", BaseVHD: *base, VMRoot: *vmRoot,
			VSwitch: *mainSwitch, AdminCredential: *credential,
			MemoryMB: 4096, CPUCount: 2,
			RegisterLabLink: &enroll,
		}
		if *base != "" {
			if err := save("local-windows", localWindows); err != nil {
				return err
			}
			builder := localWindows
			enabled := true
			builder.ProfileUsage = vmconfig.ProfileUsageLinuxImageBuilder
			builder.ExposeVirtualizationExtensions = &enabled
			builder.VirtualizationBasedSecurityOptOut = &enabled
			if err := save("local-linux-builder", builder); err != nil {
				return err
			}
		}
		profile := vmconfig.Profile{
			Target: *name, GuestOS: "linux", Distribution: "ubuntu", Release: "24.04", Architecture: "amd64",
			VMRoot: *vmRoot, VSwitch: *mainSwitch, ImageCacheRoot: *imageRoot,
			LinuxUsername: "labuser", LinuxPasswordCredential: *credential,
			MemoryMB: 4096, CPUCount: 2, DiskSizeGB: 64,
			RegisterLabLink: &enroll,
		}
		if *base != "" {
			profile.ImageBuilderProfile = "local-linux-builder"
		}
		if err := save("local-ubuntu", profile); err != nil {
			return err
		}
	}
	fmt.Printf("Registered restricted local Hyper-V host %s at %s\n", *name, *address)
	return nil
}
