//go:build windows

package main

import (
	"golang.org/x/sys/windows/registry"
)

const (
	registryKeyPath       = `SOFTWARE\LabLink`
	legacyRegistryKeyPath = `SOFTWARE\device-interaction`
)

// readTokenFromRegistry reads the auth token from HKLM\SOFTWARE\LabLink\AuthToken.
// Falls back to the legacy device-interaction registry key to ease migration.
func readTokenFromRegistry() string {
	for _, keyPath := range []string{registryKeyPath, legacyRegistryKeyPath} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		val, _, err := k.GetStringValue("AuthToken")
		k.Close()
		if err == nil && val != "" {
			return val
		}
	}
	return ""
}

// writeTokenToRegistry writes the auth token to HKLM\SOFTWARE\LabLink\AuthToken.
func writeTokenToRegistry(token string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, registryKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("AuthToken", token)
}
