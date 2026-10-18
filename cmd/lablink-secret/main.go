package main

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/nijosmsft/lablink/internal/secretstore"
	"github.com/nijosmsft/lablink/internal/security"
	"golang.org/x/term"
)

var secretVersion = "dev"

type secretReader func(prompt string) ([]byte, error)

var errSecretInputCanceled = errors.New("secret input canceled")

func main() {
	err := runMain()
	writeSecretStatus(err)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runMain() error {
	cleanup, err := prepareConsoleIO()
	if err != nil {
		return err
	}
	defer cleanup()

	return run(os.Args[1:], os.Stdout, os.Stderr, readMaskedSecret)
}

func readMaskedSecret(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("standard input is not a terminal; refusing to read a secret from a pipe or redirected file")
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("enable masked terminal input: %w", err)
	}
	defer term.Restore(fd, state)

	fmt.Fprint(os.Stderr, prompt)
	value, err := readSecretWithFeedback(os.Stdin, os.Stderr)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read masked secret: %w", err)
	}
	return value, nil
}

func readSecretWithFeedback(input io.Reader, output io.Writer) ([]byte, error) {
	reader := bufio.NewReader(input)
	value := make([]rune, 0, 32)
	defer func() {
		for i := range value {
			value[i] = 0
		}
	}()
	for {
		key, _, err := reader.ReadRune()
		if err != nil {
			return nil, err
		}
		switch key {
		case '\r', '\n':
			return []byte(string(value)), nil
		case '\b', '\x7f':
			if len(value) == 0 {
				continue
			}
			value[len(value)-1] = 0
			value = value[:len(value)-1]
			if _, err := io.WriteString(output, "\b \b"); err != nil {
				return nil, err
			}
		case '\x03':
			return nil, errSecretInputCanceled
		default:
			if unicode.IsControl(key) {
				continue
			}
			value = append(value, key)
			if _, err := io.WriteString(output, "*"); err != nil {
				return nil, err
			}
		}
	}
}

func run(args []string, stdout, stderr io.Writer, readSecret secretReader) error {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "-version") {
		fmt.Fprintf(stdout, "lablink-secret %s\n", secretVersion)
		return nil
	}
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "set":
		return runSet(args[1:], stdout, stderr, readSecret)
	case "list":
		return runList(args[1:], stdout, stderr)
	case "delete":
		return runDelete(args[1:], stdout, stderr)
	default:
		return usageError()
	}
}

func runSet(args []string, stdout, stderr io.Writer, readSecret secretReader) error {
	flags := flag.NewFlagSet("set", flag.ContinueOnError)
	flags.SetOutput(stderr)
	storePath := flags.String("store", "", "encrypted LabLink secret-store path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: lablink-secret set [--store PATH] NAME")
	}
	name, err := secretstore.ValidateName(flags.Arg(0))
	if err != nil {
		return err
	}
	path, err := resolveStorePath(*storePath)
	if err != nil {
		return err
	}
	first, err := readSecret(fmt.Sprintf("Secret value for %q: ", name))
	if err != nil {
		return err
	}
	defer clearBytes(first)
	if len(first) == 0 {
		return fmt.Errorf("secret value cannot be empty")
	}
	second, err := readSecret("Confirm secret value: ")
	if err != nil {
		return err
	}
	defer clearBytes(second)
	if len(first) != len(second) || subtle.ConstantTimeCompare(first, second) != 1 {
		return fmt.Errorf("secret values do not match")
	}
	if err := secretstore.Open(path).Set(name, string(first)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Secret %q saved securely in %s.\n", name, path)
	return nil
}

func runList(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	storePath := flags.String("store", "", "encrypted LabLink secret-store path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("usage: lablink-secret list [--store PATH]")
	}
	path, err := resolveStorePath(*storePath)
	if err != nil {
		return err
	}
	names, err := secretstore.Open(path).List()
	if err != nil {
		return err
	}
	for _, name := range names {
		fmt.Fprintln(stdout, name)
	}
	return nil
}

func runDelete(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("delete", flag.ContinueOnError)
	flags.SetOutput(stderr)
	storePath := flags.String("store", "", "encrypted LabLink secret-store path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: lablink-secret delete [--store PATH] NAME")
	}
	name, err := secretstore.ValidateName(flags.Arg(0))
	if err != nil {
		return err
	}
	path, err := resolveStorePath(*storePath)
	if err != nil {
		return err
	}
	if err := secretstore.Open(path).Delete(name); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Secret %q deleted from %s.\n", name, path)
	return nil
}

func resolveStorePath(explicit string) (string, error) {
	if value := strings.TrimSpace(explicit); value != "" {
		return filepath.Clean(value), nil
	}
	if value := strings.TrimSpace(security.FirstPresentEnv("LABLINK_SECRETS_FILE")); value != "" {
		return filepath.Clean(value), nil
	}
	configDir := security.FirstPresentEnv("LABLINK_HOME", "DEVICE_INTERACTION_HOME")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determine home directory: %w", err)
		}
		configDir = filepath.Join(home, ".lablink")
	}
	return filepath.Join(configDir, "secrets.json"), nil
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func usageError() error {
	return fmt.Errorf("usage: lablink-secret <set|list|delete> [options]")
}
