//go:build !windows

package management

import "os"

func setPrivateFilePermissions(file *os.File) error {
	return file.Chmod(0600)
}
