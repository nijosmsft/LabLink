package linuxvm

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-crypt/crypt/algorithm/shacrypt"
)

const CIDATAVolumeLabel = "CIDATA"

const DefaultHyperVDHCPNetworkConfig = `version: 2
ethernets:
  hyperv:
    match:
      driver: hv_netvsc
    dhcp4: true
    dhcp6: true`

var (
	hostnamePattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	usernamePattern    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	sha512CryptPattern = regexp.MustCompile(`^\$6\$(?:rounds=[0-9]+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$`)
)

type SeedConfig struct {
	Hostname             string
	Username             string
	SSHPublicKey         string
	PasswordHash         string
	AllowSSHPasswordAuth bool
	NetworkConfig        string
	NodeName             string
	Port                 int
}

func ValidateHostname(value string) error {
	if len(value) == 0 || len(value) > 63 || !hostnamePattern.MatchString(value) {
		return fmt.Errorf("invalid Linux hostname %q: use a lowercase RFC1123 label of 1-63 characters", value)
	}
	return nil
}

func ValidateUsername(value string) error {
	if !usernamePattern.MatchString(value) || value == "root" {
		return fmt.Errorf("invalid Linux username %q: use 1-32 lowercase letters, digits, underscore, or hyphen, starting with a letter or underscore, and not root", value)
	}
	return nil
}

func ValidateSSHPublicKey(value string) error {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) < 2 {
		return fmt.Errorf("SSH public key must contain an algorithm and base64 payload")
	}
	switch fields[0] {
	case "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
	default:
		return fmt.Errorf("unsupported SSH public key algorithm %q", fields[0])
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(decoded) < 16 {
		return fmt.Errorf("SSH public key has an invalid base64 payload")
	}
	return nil
}

func HashPasswordSHA512(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("Linux password credential is empty")
	}
	hasher, err := shacrypt.NewSHA512()
	if err != nil {
		return "", fmt.Errorf("initialize SHA-512 crypt: %w", err)
	}
	digest, err := hasher.Hash(password)
	if err != nil {
		return "", fmt.Errorf("generate SHA-512 crypt hash: %w", err)
	}
	hash := digest.Encode()
	if !sha512CryptPattern.MatchString(hash) {
		return "", fmt.Errorf("generated password hash is not Linux SHA-512 crypt")
	}
	return hash, nil
}

func validateAccess(config SeedConfig) error {
	hasKey := strings.TrimSpace(config.SSHPublicKey) != ""
	hasPassword := strings.TrimSpace(config.PasswordHash) != ""
	if !hasKey && !hasPassword {
		return fmt.Errorf("at least one SSH public key or Linux password credential is required")
	}
	if hasKey {
		if err := ValidateSSHPublicKey(config.SSHPublicKey); err != nil {
			return err
		}
	}
	if hasPassword && !sha512CryptPattern.MatchString(config.PasswordHash) {
		return fmt.Errorf("Linux password hash must be SHA-512 crypt")
	}
	if config.AllowSSHPasswordAuth != hasPassword {
		if hasPassword {
			return fmt.Errorf("allow_ssh_password_auth must be true when a Linux password credential is configured")
		}
		return fmt.Errorf("allow_ssh_password_auth requires a Linux password credential")
	}
	return nil
}

func UserData(config SeedConfig) ([]byte, error) {
	if err := ValidateHostname(config.Hostname); err != nil {
		return nil, err
	}
	if err := ValidateUsername(config.Username); err != nil {
		return nil, err
	}
	if err := validateAccess(config); err != nil {
		return nil, err
	}

	var user strings.Builder
	fmt.Fprintf(&user, `#cloud-config
preserve_hostname: false
hostname: %s
fqdn: %s
manage_etc_hosts: true
ssh_pwauth: %t
disable_root: true
users:
  - name: %s
    lock_passwd: %t
`, yamlScalar(config.Hostname), yamlScalar(config.Hostname), config.AllowSSHPasswordAuth,
		yamlScalar(config.Username), !config.AllowSSHPasswordAuth)
	if config.PasswordHash != "" {
		fmt.Fprintf(&user, "    passwd: %s\n", yamlScalar(config.PasswordHash))
	}
	user.WriteString(`    shell: /bin/bash
    groups: [adm, sudo]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
`)
	if strings.TrimSpace(config.SSHPublicKey) != "" {
		fmt.Fprintf(&user, "    ssh_authorized_keys:\n      - %s\n", yamlScalar(strings.TrimSpace(config.SSHPublicKey)))
	}
	user.WriteString(`runcmd:
  - [bash, -c, "set -eu; mkdir -p /run/lablink-cidata; mount -o ro LABEL=CIDATA /run/lablink-cidata; trap 'umount /run/lablink-cidata || true' EXIT; /bin/bash /run/lablink-cidata/install-lablink.sh"]
final_message: "LabLink NoCloud provisioning complete"
`)
	return []byte(user.String()), nil
}

func MetaData(config SeedConfig) ([]byte, error) {
	if err := ValidateHostname(config.Hostname); err != nil {
		return nil, err
	}
	if strings.TrimSpace(config.NodeName) == "" {
		return nil, fmt.Errorf("LabLink node name is required")
	}
	return []byte(fmt.Sprintf(
		"dsmode: local\ninstance-id: %s\nlocal-hostname: %s\n",
		yamlScalar("lablink-"+config.NodeName), yamlScalar(config.Hostname),
	)), nil
}

func InstallerScript(config SeedConfig) ([]byte, error) {
	if strings.TrimSpace(config.NodeName) == "" {
		return nil, fmt.Errorf("LabLink node name is required")
	}
	if config.Port <= 0 || config.Port > 65535 {
		return nil, fmt.Errorf("LabLink port must be between 1 and 65535")
	}
	passwordAuth := "no"
	if config.AllowSSHPasswordAuth {
		passwordAuth = "yes"
	}
	script := fmt.Sprintf(`#!/bin/bash
set -Eeuo pipefail
umask 077
status=/var/log/lablink-install.status
fail() {
  rc=$?
  printf 'failed rc=%%s line=%%s\n' "$rc" "${BASH_LINENO[0]:-unknown}" > "$status"
  logger -t lablink-install "installation failed rc=$rc"
  exit "$rc"
}
trap fail ERR

src="$(cd "$(dirname "$0")" && pwd)"
for file in lablink-agent ca.crt server.crt server.key agent.token; do
  test -s "$src/$file"
done

install -d -m 0755 /opt/lablink /etc/lablink /etc/lablink/tls
install -d -o root -g root -m 0700 /var/lib/lablink-agent
install -m 0755 "$src/lablink-agent" /opt/lablink/lablink-agent
install -m 0644 "$src/ca.crt" /etc/lablink/tls/ca.crt
install -m 0644 "$src/server.crt" /etc/lablink/tls/server.crt
install -m 0600 "$src/server.key" /etc/lablink/tls/server.key
install -m 0600 "$src/agent.token" /etc/lablink/agent.token
chown -R root:root /opt/lablink /etc/lablink

cat > /etc/systemd/system/lablink-agent.service <<'EOF'
[Unit]
Description=LabLink Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/lablink/lablink-agent --listen :%d --transport mtls --auth-token-file /etc/lablink/agent.token --tls-ca /etc/lablink/tls/ca.crt --tls-cert /etc/lablink/tls/server.crt --tls-key /etc/lablink/tls/server.key
Restart=always
RestartSec=2
User=root
NoNewPrivileges=true
PrivateTmp=true
Environment=LABLINK_AGENT_DATA=/var/lib/lablink-agent

[Install]
WantedBy=multi-user.target
EOF

install -d -m 0755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-lablink.conf <<'EOF'
PasswordAuthentication %s
KbdInteractiveAuthentication no
PermitRootLogin no
EOF

install -d -m 0755 /etc/cloud/cloud.cfg.d
cat > /etc/cloud/cloud.cfg.d/99-lablink-datasource-cache.cfg <<'EOF'
manual_cache_clean: true
EOF

systemctl daemon-reload
systemctl enable --now hv-kvp-daemon.service
systemctl enable --now ssh.service
/usr/sbin/sshd -t
systemctl restart ssh.service
systemctl enable --now lablink-agent.service
systemctl is-active --quiet lablink-agent.service
printf 'ok port=%d\n' > "$status"
logger -t lablink-install "installation complete"
`, config.Port, passwordAuth, config.Port)
	return []byte(script), nil
}

func Files(config SeedConfig) (map[string][]byte, error) {
	userData, err := UserData(config)
	if err != nil {
		return nil, err
	}
	metaData, err := MetaData(config)
	if err != nil {
		return nil, err
	}
	installer, err := InstallerScript(config)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		"user-data":          userData,
		"meta-data":          metaData,
		"install-lablink.sh": installer,
	}
	networkConfig := strings.TrimSpace(config.NetworkConfig)
	if networkConfig == "" {
		networkConfig = DefaultHyperVDHCPNetworkConfig
	}
	if strings.IndexByte(networkConfig, 0) >= 0 {
		return nil, fmt.Errorf("network-config contains a NUL byte")
	}
	files["network-config"] = []byte(networkConfig + "\n")
	return files, nil
}

func yamlScalar(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
