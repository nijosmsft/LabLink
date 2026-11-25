//go:build !linux

package appliance

import (
	"context"
	"fmt"
)

func PinManagementIPv4(context.Context, string, string, string, []string) (string, string, error) {
	return "", "", fmt.Errorf("management IPv4 pinning requires Linux networkd")
}

func RollbackManagementIPv4(context.Context) error {
	return fmt.Errorf("management IPv4 rollback requires Linux networkd")
}
