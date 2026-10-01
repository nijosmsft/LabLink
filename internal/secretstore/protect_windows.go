//go:build windows

package secretstore

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type dpapiProtector struct{}

func newProtector(_ string) (protector, error) {
	return dpapiProtector{}, nil
}

func dataBlob(data []byte) windows.DataBlob {
	if len(data) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}

func copyAndFreeBlob(blob windows.DataBlob) []byte {
	if blob.Data == nil || blob.Size == 0 {
		return nil
	}
	out := append([]byte(nil), unsafe.Slice(blob.Data, int(blob.Size))...)
	_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(blob.Data))))
	return out
}

func (dpapiProtector) Protect(data []byte) ([]byte, error) {
	in := dataBlob(data)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("DPAPI protect: %w", err)
	}
	return copyAndFreeBlob(out), nil
}

func (dpapiProtector) Unprotect(data []byte) ([]byte, error) {
	in := dataBlob(data)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("DPAPI unprotect: %w", err)
	}
	return copyAndFreeBlob(out), nil
}
