package leasing

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Identity is the layered agent identity defined in memo Section 5.
//
// EffectiveID is what gets recorded as agent_id on the lease row. The other
// components are recorded separately so a post-mortem can disambiguate two
// agents that share an effective id.
type Identity struct {
	Cookie      string    // ~/.lablink/agent-cookie, 8 hex chars, per-user
	Hostname    string    // os.Hostname()
	PID         int       // os.Getpid()
	StartTime   time.Time // process start time, for sweeper
	RandSuffix  string    // 4 hex chars, per-process (PID-reuse disambiguation)
	EffectiveID string    // user override (LABLINK_AGENT_ID) or layered default
}

// Empty reports whether the identity is zero-valued.
func (i Identity) Empty() bool {
	return i.EffectiveID == "" && i.Cookie == "" && i.Hostname == "" && i.PID == 0
}

var (
	defaultIdentityOnce sync.Once
	defaultIdentityVal  Identity
)

// Default returns the layered identity for THIS process, computing it once
// per program run.
//
// Cookie source: ~/.lablink/agent-cookie (created on first call if missing).
// Override priority: LABLINK_AGENT_ID env var > layered default.
func Default() Identity {
	defaultIdentityOnce.Do(func() {
		defaultIdentityVal = buildIdentity(time.Now())
	})
	return defaultIdentityVal
}

// buildIdentity constructs an identity using the supplied start time as the
// process start. Exposed for tests.
func buildIdentity(start time.Time) Identity {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	pid := os.Getpid()
	cookie := loadOrCreateCookie()
	suffix := randHex(2)
	effective := strings.TrimSpace(os.Getenv("LABLINK_AGENT_ID"))
	if effective == "" {
		effective = fmt.Sprintf("%s-%s-%d-%s", cookie, hostname, pid, suffix)
	}
	return Identity{
		Cookie:      cookie,
		Hostname:    hostname,
		PID:         pid,
		StartTime:   start,
		RandSuffix:  suffix,
		EffectiveID: effective,
	}
}

// DefaultLeaseDir returns the directory holding the SQLite leases db plus
// the agent-cookie file. Mirrors the design memo (~/.lablink).
func DefaultLeaseDir() string {
	if v := strings.TrimSpace(os.Getenv("LABLINK_HOME")); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// On a hostile environment where HOME is unset, fall back to CWD.
		// The server boot path will surface this via the open error if the
		// directory is unwritable.
		home = "."
	}
	return filepath.Join(home, ".lablink")
}

// DefaultDBPath returns the conventional location for leases.db.
func DefaultDBPath() string {
	return filepath.Join(DefaultLeaseDir(), "leases.db")
}

func cookiePath() string {
	return filepath.Join(DefaultLeaseDir(), "agent-cookie")
}

func loadOrCreateCookie() string {
	p := cookiePath()
	if data, err := os.ReadFile(p); err == nil {
		c := strings.TrimSpace(string(data))
		if len(c) >= 4 && isHex(c) {
			return c
		}
	}
	cookie := randHex(4)
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, []byte(cookie+"\n"), 0o600)
	return cookie
}

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never returns an error in practice on supported
		// platforms; fall back to a time-derived seed so we still
		// produce a usable id.
		ns := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(ns >> (uint(i) * 8))
		}
	}
	return hex.EncodeToString(b)
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return len(s) > 0
}

// newLeaseID returns a "lse-<8hex>" identifier.
func newLeaseID() string {
	return "lse-" + randHex(4)
}
