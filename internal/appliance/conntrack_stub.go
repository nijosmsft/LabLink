//go:build !linux

package appliance

import "context"

type LinuxConntrackConfig struct {
	Executor CommandExecutor
	Parser   ConntrackParser
}

type LinuxConntrack struct{}

func NewLinuxConntrack(LinuxConntrackConfig) (*LinuxConntrack, error) {
	return nil, ErrUnsupportedPlatform
}

func (*LinuxConntrack) Count(context.Context, ConntrackFilter) (int, error) {
	return 0, ErrUnsupportedPlatform
}

func (*LinuxConntrack) RetireExact(context.Context, ConntrackFilter) error {
	return ErrUnsupportedPlatform
}
