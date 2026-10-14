package linuximage

import (
	"bufio"
	"fmt"
	"strings"
)

// ParseSHA256SUMS returns the checksum for the exact requested file.
// Both GNU text ("  file") and binary (" *file") markers are accepted.
func ParseSHA256SUMS(data []byte, filename string) (string, error) {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return "", fmt.Errorf("filename is required")
	}
	var found string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(line) < 66 {
			continue
		}
		hash := line[:64]
		separator := line[64:]
		if separator == "" || (separator[0] != ' ' && separator[0] != '\t') {
			continue
		}
		name := strings.TrimLeft(separator, " \t")
		if strings.HasPrefix(name, "*") {
			name = strings.TrimPrefix(name, "*")
		}
		if name != filename {
			continue
		}
		normalized, err := normalizeSHA256(hash)
		if err != nil {
			return "", fmt.Errorf("checksum for %s: %w", filename, err)
		}
		if found != "" {
			return "", fmt.Errorf("SHA256SUMS contains multiple entries for %s", filename)
		}
		found = normalized
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read SHA256SUMS: %w", err)
	}
	if found == "" {
		return "", fmt.Errorf("SHA256SUMS has no exact entry for %s", filename)
	}
	return found, nil
}
