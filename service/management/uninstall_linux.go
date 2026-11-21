package management

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func secureRootFile(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory {
		return errors.New("uninstall files must be owned and writable only by root")
	}
	return nil
}
func nativeInstallation(executable string) (string, error) {
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", err
	}
	if resolved != "/usr/lib/packettale/packettale-core" {
		return "", errors.New("remote uninstall requires the native packettale package")
	}
	if err = secureRootFile("/usr/sbin/packettale-uninstall", false); err != nil {
		return "", err
	}
	return "/usr/lib/packettale", nil
}
func newUninstallDirectory() (string, error) {
	return os.MkdirTemp("/var/lib", "packettale-uninstall-")
}

// Linux can unlink a running executable. Use the already installed binary so
// SELinux retains its native executable label, rather than executing var_lib_t.
func prepareUninstallWorker(executable, _ string) (string, error) {
	return executable, nil
}
func validateUninstallExecutable(executable, _ string) error {
	if _, err := nativeInstallation(executable); err != nil {
		return err
	}
	return secureRootFile(executable, false)
}
func prepareNativeUninstaller(_ string, directory string) error {
	return copyUninstallFile("/usr/sbin/packettale-uninstall", filepath.Join(directory, "native-uninstall.sh"))
}
func startUninstallWorker(ctx context.Context, worker, request, id string) error {
	// A separate transient service escapes packettale.service's cgroup and
	// PrivateTmp namespace, so stopping/removing the package cannot kill it.
	return exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--collect", "--property=Type=exec", "--unit=packettale-uninstall-"+id, worker, "uninstall-worker", request).Run()
}
func validateUninstallWorker(directory, request string) error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall worker requires root")
	}
	if filepath.Dir(directory) != "/var/lib" {
		return errors.New("invalid uninstall worker directory")
	}
	if err := secureRootFile(directory, true); err != nil {
		return err
	}
	return secureRootFile(request, false)
}
func executeNativeUninstall(ctx context.Context, install, directory string, purge bool) (int, error) {
	if install != "/usr/lib/packettale" {
		return -1, errors.New("invalid native installation")
	}
	args := []string{filepath.Join(directory, "native-uninstall.sh")}
	if purge {
		args = append(args, "--purge")
	}
	err := exec.CommandContext(ctx, "/bin/sh", args...).Run()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), err
		}
		return -1, err
	}
	return 0, nil
}
func cleanupUninstallWorker(directory string) { _ = os.RemoveAll(directory) }
func nativeDataDirectory() (string, error)    { return "/var/lib/packettale", nil }
