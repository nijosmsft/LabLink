// Package flock provides a small cross-process advisory file lock.
//
// Multiple LabLinkServer processes can share the same operator config
// directory (one per AI client session). Without an OS-level lock, plain
// in-process mutexes are not enough to keep nodes.json or history.jsonl
// consistent across processes. This package wraps platform-specific
// locking primitives behind a single Lock/Unlock interface.
package flock

import "os"

// Locker is an exclusive, blocking advisory file lock. Lock blocks until the
// lock is acquired. Close releases the lock and the underlying file handle.
type Locker struct {
	f *os.File
}

// Lock opens (creating if needed) the named file and acquires an exclusive
// advisory lock on it. Callers must Close the returned Locker to release it.
//
// The lock file itself is a sidecar — it never holds data. Use a path like
// "<target>.lock" so that operations on <target> can be serialised across
// processes without holding a handle on <target> itself.
func Lock(path string) (*Locker, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	if err := platformLock(f); err != nil {
		f.Close()
		return nil, err
	}
	return &Locker{f: f}, nil
}

// Close releases the lock and closes the file handle.
func (l *Locker) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = platformUnlock(l.f)
	err := l.f.Close()
	l.f = nil
	return err
}
