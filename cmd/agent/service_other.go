//go:build !windows

package main

import (
	"errors"

	"github.com/nijosmsft/lablink/internal/security"
)

func isWindowsService() bool { return false }

func runAsService() error {
	return errors.New("windows services not supported on this platform")
}

func installService(binPath string, port int, cfg security.ServerTransportConfig, tokenFile string) error {
	return errors.New("windows services not supported on this platform")
}

func uninstallService() error {
	return errors.New("windows services not supported on this platform")
}
