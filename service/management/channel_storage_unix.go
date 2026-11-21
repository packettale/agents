//go:build !windows

package management

// The service owns this 0600 file. Hardware-backed storage is optional.
func protectIdentity(data []byte) ([]byte, error)   { return data, nil }
func unprotectIdentity(data []byte) ([]byte, error) { return data, nil }
