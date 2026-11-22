//go:build !windows

package main

import "fmt"

const hyperVServiceName = "LabLinkHyperV"

func enableHyperVServicePrivileges() error {
	return fmt.Errorf("Hyper-V-only service mode requires Windows")
}

func installHyperVService() error {
	return fmt.Errorf("Hyper-V-only service installation requires Windows")
}
