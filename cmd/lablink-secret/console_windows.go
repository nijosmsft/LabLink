//go:build windows

package main

import (
	"fmt"
	"os"
)

const secretConsoleEnv = "LABLINK_SECRET_NEW_CONSOLE"

func prepareConsoleIO() (func(), error) {
	if os.Getenv(secretConsoleEnv) != "1" {
		return func() {}, nil
	}

	input, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open console input: %w", err)
	}
	output, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("open console output: %w", err)
	}

	os.Stdin = input
	os.Stdout = output
	os.Stderr = output
	return func() {
		_ = input.Close()
		_ = output.Close()
	}, nil
}
