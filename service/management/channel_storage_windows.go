//go:build windows

package management

import (
	"bytes"
	"errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

var identityPrefix = []byte("PacketTale-DPAPI-1\n")

func protectIdentity(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty device identity")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append(bytes.Clone(identityPrefix), unsafe.Slice(out.Data, int(out.Size))...), nil
}
func unprotectIdentity(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, identityPrefix) || len(data) <= len(identityPrefix) {
		return nil, errors.New("device identity is not protected")
	}
	data = data[len(identityPrefix):]
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return bytes.Clone(unsafe.Slice(out.Data, int(out.Size))), nil
}
