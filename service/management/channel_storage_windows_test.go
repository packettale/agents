//go:build windows

package management

import (
	"bytes"
	"testing"
)

func TestDeviceIdentityUsesMachineDPAPI(t *testing.T) {
	data := []byte("private-key-and-device-credential-test-sentinel")
	protected, err := protectIdentity(data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(protected, data) {
		t.Fatal("identity was stored as plaintext")
	}
	restored, err := unprotectIdentity(protected)
	if err != nil || !bytes.Equal(restored, data) {
		t.Fatal("DPAPI identity did not round trip")
	}
	protected[len(protected)-1] ^= 1
	if _, err = unprotectIdentity(protected); err == nil {
		t.Fatal("corrupted DPAPI blob accepted")
	}
	if _, err = unprotectIdentity(data); err == nil {
		t.Fatal("plaintext identity accepted")
	}
}
