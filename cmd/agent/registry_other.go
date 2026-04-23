//go:build !windows

package main

func readTokenFromRegistry() string { return "" }

func writeTokenToRegistry(token string) error { return nil }
