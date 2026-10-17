package main

import (
	"encoding/json"
	"os"
)

const secretStatusFileEnv = "LABLINK_SECRET_STATUS_FILE"

type secretStatus struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func writeSecretStatus(runErr error) {
	path := os.Getenv(secretStatusFileEnv)
	if path == "" {
		return
	}
	status := secretStatus{OK: runErr == nil}
	if runErr != nil {
		status.Error = runErr.Error()
	}
	data, err := json.Marshal(status)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0600)
}
