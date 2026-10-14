package linuxvm

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func testKey() string {
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) + " lab"
}

func TestNoCloudFilesAccessModesAndPasswordSecrecy(t *testing.T) {
	password := "Correct Horse Battery Staple!"
	hash, err := HashPasswordSHA512(password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$6$rounds=500000$") || strings.Contains(hash, password) {
		t.Fatalf("unexpected SHA-512 crypt hash %q", hash)
	}
	tests := []struct {
		name          string
		key           string
		hash          string
		allowPassword bool
		wantKey       bool
		wantPassword  bool
	}{
		{name: "key-only", key: testKey(), wantKey: true},
		{name: "password-only", hash: hash, allowPassword: true, wantPassword: true},
		{name: "key-and-password", key: testKey(), hash: hash, allowPassword: true, wantKey: true, wantPassword: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := Files(SeedConfig{
				Hostname: "ubuntu-vm", Username: "lab", SSHPublicKey: tt.key,
				PasswordHash: tt.hash, AllowSSHPasswordAuth: tt.allowPassword,
				NodeName: "ubuntu-vm", Port: 9091,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"meta-data", "user-data", "install-lablink.sh"} {
				if len(files[name]) == 0 {
					t.Fatalf("missing %s", name)
				}
			}
			userData := string(files["user-data"])
			var cloudConfig map[string]any
			if err := yaml.Unmarshal(files["user-data"], &cloudConfig); err != nil {
				t.Fatalf("invalid cloud-config YAML: %v\n%s", err, userData)
			}
			if strings.Contains(userData, password) {
				t.Fatal("plaintext password leaked into cloud-config")
			}
			if strings.Contains(userData, "\n    passwd: ") != tt.wantPassword {
				t.Fatalf("password hash presence mismatch:\n%s", userData)
			}
			if strings.Contains(userData, "ssh_authorized_keys:") != tt.wantKey {
				t.Fatalf("SSH key presence mismatch:\n%s", userData)
			}
			wantPWAuth := "ssh_pwauth: false"
			if tt.allowPassword {
				wantPWAuth = "ssh_pwauth: true"
			}
			for _, want := range []string{wantPWAuth, "disable_root: true", "LABEL=CIDATA", "LabLink NoCloud provisioning complete"} {
				if !strings.Contains(userData, want) {
					t.Fatalf("user-data missing %q:\n%s", want, userData)
				}
			}
			if strings.Contains(strings.ToLower(userData), "datasourceazure") {
				t.Fatalf("user-data contains obsolete datasource dependency:\n%s", userData)
			}
		})
	}
}

func TestNoCloudMetaAndOptionalNetworkConfig(t *testing.T) {
	files, err := Files(SeedConfig{
		Hostname: "ubuntu-vm", Username: "lab", SSHPublicKey: testKey(),
		NodeName: "ubuntu-vm", Port: 9091,
		NetworkConfig: "version: 2\nethernets:\n  eth0:\n    dhcp4: true",
	})
	if err != nil {
		t.Fatal(err)
	}
	meta := string(files["meta-data"])
	if !strings.Contains(meta, "dsmode: local") ||
		!strings.Contains(meta, "instance-id: 'lablink-ubuntu-vm'") ||
		!strings.Contains(meta, "local-hostname: 'ubuntu-vm'") {
		t.Fatalf("unexpected meta-data:\n%s", meta)
	}
	if !strings.Contains(string(files["network-config"]), "dhcp4: true") {
		t.Fatalf("optional network-config missing: %#v", files)
	}
}

func TestSeedFilesDefaultToHyperVDHCPNetworkConfig(t *testing.T) {
	files, err := Files(SeedConfig{
		Hostname: "vm-1", Username: "labadmin", SSHPublicKey: testKey(),
		NodeName: "vm-1", Port: 9091,
	})
	if err != nil {
		t.Fatal(err)
	}
	network := string(files["network-config"])
	for _, want := range []string{"version: 2", "driver: hv_netvsc", "dhcp4: true", "dhcp6: true"} {
		if !strings.Contains(network, want) {
			t.Errorf("default network-config missing %q:\n%s", want, network)
		}
	}
}

func TestSeedInstallerSecurity(t *testing.T) {
	files, err := Files(SeedConfig{
		Hostname: "ubuntu-vm", Username: "lab", SSHPublicKey: testKey(),
		NodeName: "ubuntu-vm", Port: 9091,
	})
	if err != nil {
		t.Fatal(err)
	}
	install := string(files["install-lablink.sh"])
	for _, want := range []string{
		"/opt/lablink", "/etc/lablink", "install -m 0600", "lablink-agent.service",
		"install -d -o root -g root -m 0700 /var/lib/lablink-agent",
		"Environment=LABLINK_AGENT_DATA=/var/lib/lablink-agent",
		"NoNewPrivileges=true", "PrivateTmp=true",
		"enable --now hv-kvp-daemon.service", "enable --now ssh.service",
		"PasswordAuthentication no", "PermitRootLogin no", "systemctl restart ssh.service",
		"/etc/cloud/cloud.cfg.d/99-lablink-datasource-cache.cfg", "manual_cache_clean: true",
		"trap fail ERR", "systemctl is-active --quiet lablink-agent.service",
	} {
		if !strings.Contains(install, want) {
			t.Errorf("installer missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"BEGIN PRIVATE", "Correct Horse", "ProtectSystem=strict", "ReadWritePaths=", "walinuxagent",
		"cloud-init.disabled",
	} {
		if strings.Contains(strings.ToLower(install), strings.ToLower(forbidden)) {
			t.Fatalf("installer contains forbidden content %q", forbidden)
		}
	}
}

func TestLinuxInputValidation(t *testing.T) {
	for _, value := range []string{"", "-bad", "BAD", strings.Repeat("a", 64)} {
		if ValidateHostname(value) == nil {
			t.Errorf("hostname %q unexpectedly valid", value)
		}
	}
	for _, value := range []string{"root", "Bad", "bad user", "-bad"} {
		if ValidateUsername(value) == nil {
			t.Errorf("username %q unexpectedly valid", value)
		}
	}
	for _, value := range []string{"", "ssh-ed25519 !!!", "ssh-dss AAAA"} {
		if ValidateSSHPublicKey(value) == nil {
			t.Errorf("key %q unexpectedly valid", value)
		}
	}
	if _, err := UserData(SeedConfig{Hostname: "vm", Username: "lab"}); err == nil {
		t.Fatal("expected missing access method error")
	}
}

func TestInstallerIsIdempotent(t *testing.T) {
	data, err := InstallerScript(SeedConfig{NodeName: "node", Port: 9091})
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	if strings.Contains(script, "useradd") || strings.Contains(script, "mkdir ") && !strings.Contains(script, "install -d") {
		t.Fatal("installer contains a non-idempotent primitive")
	}
}
