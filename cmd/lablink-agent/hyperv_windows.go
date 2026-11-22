//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const hyperVServiceName = "LabLinkHyperV"

func installHyperVService() error {
	host, _, err := net.SplitHostPort(*listenAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("restricted service requires a numeric loopback listen address")
	}
	if !filepath.IsAbs(*hyperVPolicyPath) || *transportMode != "mtls" ||
		*tlsCAPath == "" || *tlsCertPath == "" || *tlsKeyPath == "" || *authTokenFile == "" {
		return fmt.Errorf("installer must supply an absolute policy path and mTLS/authentication files")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	binary := filepath.Join(filepath.Dir(*hyperVPolicyPath), "bin", "lablink-agent.exe")
	service, err := manager.CreateService(hyperVServiceName, binary, mgr.Config{
		DisplayName: "LabLink Local Hyper-V", StartType: mgr.StartAutomatic,
		ServiceStartName: `NT SERVICE\` + hyperVServiceName,
		Description:      "Loopback-only structured Hyper-V VM management; no arbitrary execution",
	}, "--hyperv-only", "--hyperv-policy", *hyperVPolicyPath, "--listen", *listenAddr,
		"--transport", "mtls", "--auth-token-file", *authTokenFile,
		"--tls-ca", *tlsCAPath, "--tls-cert", *tlsCertPath, "--tls-key", *tlsKeyPath)
	if err != nil {
		return err
	}
	return service.Close()
}

func enableHyperVServicePrivileges() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &token); err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+hyperVServiceName)
	if err != nil {
		return err
	}
	if !user.User.Sid.Equals(sid) {
		return fmt.Errorf("Hyper-V-only agent must run as NT SERVICE\\%s, never as SYSTEM or an interactive account", hyperVServiceName)
	}
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return err
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.Equals(admin) && group.Attributes&windows.SE_GROUP_ENABLED != 0 {
			return fmt.Errorf("restricted Hyper-V service must not be a member of Administrators")
		}
	}
	for _, privilege := range []string{"SeManageVolumePrivilege", "SeBackupPrivilege", "SeRestorePrivilege"} {
		var id windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privilege), &id); err != nil {
			return err
		}
		state := windows.Tokenprivileges{PrivilegeCount: 1}
		state.Privileges[0] = windows.LUIDAndAttributes{Luid: id, Attributes: windows.SE_PRIVILEGE_ENABLED}
		if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
			return fmt.Errorf("enable required restricted-service privilege %s: %w", privilege, err)
		}
		if err := requireHyperVPrivilege(token, id); err != nil {
			return fmt.Errorf("restricted-service token is missing required privilege %s", privilege)
		}
	}
	return nil
}

func requireHyperVPrivilege(token windows.Token, id windows.LUID) error {
	var size uint32
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size); err != windows.ERROR_INSUFFICIENT_BUFFER {
		return fmt.Errorf("query token privileges: %v", err)
	}
	if size < 4 {
		return fmt.Errorf("invalid token privilege response size")
	}
	data := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &data[0], size, &size); err != nil {
		return err
	}
	if len(data) < 4 {
		return fmt.Errorf("invalid token privilege response")
	}
	count := binary.LittleEndian.Uint32(data[:4])
	if uint64(count)*12+4 > uint64(len(data)) {
		return fmt.Errorf("invalid token privilege count")
	}
	for i := uint32(0); i < count; i++ {
		offset := 4 + int(i)*12
		if binary.LittleEndian.Uint32(data[offset:]) == id.LowPart &&
			binary.LittleEndian.Uint32(data[offset+4:]) == uint32(id.HighPart) &&
			binary.LittleEndian.Uint32(data[offset+8:])&windows.SE_PRIVILEGE_ENABLED != 0 {
			return nil
		}
	}
	return fmt.Errorf("required privilege is not enabled")
}
