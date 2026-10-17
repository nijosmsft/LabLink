//go:build !windows

package main

func prepareConsoleIO() (func(), error) {
	return func() {}, nil
}
