package mcptools

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func newRemoteStageID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate remote staging ID: %w", err)
	}
	return hex.EncodeToString(id[:]), nil
}
