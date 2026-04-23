//go:build windows

package flock

import (
	"os"

	"golang.org/x/sys/windows"
)

// platformLock acquires an exclusive lock on the entire file using
// LockFileEx with LOCKFILE_EXCLUSIVE_LOCK. The call blocks (no
// LOCKFILE_FAIL_IMMEDIATELY) until the lock is granted.
//
// The lock is released when the file handle is closed, which Locker.Close
// does after calling platformUnlock.
func platformLock(f *os.File) error {
	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)
	return windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 0xFFFFFFFF, 0xFFFFFFFF, ol)
}

func platformUnlock(f *os.File) error {
	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(h, 0, 0xFFFFFFFF, 0xFFFFFFFF, ol)
}
