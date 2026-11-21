package updates

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/base/utils"
)

func (u *Updater) upgrade(downloader *Downloader, ignoreVersion bool) error {
	// Resource readers acquire this lock before consulting the index as well.
	u.resourceLock.Lock()
	defer u.resourceLock.Unlock()
	// Lock index for the upgrade.
	u.indexLock.Lock()
	defer u.indexLock.Unlock()

	// Check if we should upgrade at all.
	if !ignoreVersion && u.index != nil {
		if err := u.index.ShouldUpgradeTo(downloader.index); err != nil {
			return fmt.Errorf("cannot upgrade: %w", ErrNoUpdateAvailable)
		}
	}

	previousFiles, err := u.existingUpgradeTargets(downloader.index)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(u.cfg.PurgeDirectory); err != nil {
		return fmt.Errorf("clear upgrade backup directory: %w", err)
	}
	if err := utils.EnsureDirectory(u.cfg.PurgeDirectory, utils.PublicReadExecPermission); err != nil {
		return fmt.Errorf("create upgrade backup directory: %w", err)
	}

	// Only attempt recovery after preparing a fresh backup directory.
	previousIndex := u.index
	installedFiles, upgradeError := u.upgradeMoveFiles(downloader)
	if upgradeError == nil {
		// Files upgraded successfully.
		// Applying post-upgrade tasks, if any.
		upgradeError = u.applyPostUpgradeCommands()
	}

	if upgradeError == nil {
		return nil
	}

	// Attempt to recover from failed upgrade.
	cleanupErr := u.removeIntroducedArtifacts(previousFiles, installedFiles)
	recoveryErr := errors.Join(cleanupErr, u.recoverFromFailedUpgrade())
	if recoveryErr == nil {
		u.index = previousIndex
		return fmt.Errorf("upgrade failed, but recovery was successful: %w", upgradeError)
	}

	// Recovery failed too.
	return fmt.Errorf("upgrade (including recovery) failed: %w", errors.Join(upgradeError, recoveryErr))
}

func (u *Updater) upgradeMoveFiles(downloader *Downloader) ([]string, error) {
	// Important:
	// We assume that the downloader has done its job and all artifacts are verified.
	// The caller has prepared a fresh purge directory. Files will be moved here.
	// In case the files are copied, they are verified in the process.

	// Move current version files into purge folder.
	if u.index != nil {
		log.Debugf("updates/%s: removing the old version (v%s from %s)", u.cfg.Name, u.index.Version, u.index.Published)
	}
	files, err := os.ReadDir(u.cfg.Directory)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read current directory: %w", err)
		}
		err := utils.EnsureDirectory(u.cfg.PurgeDirectory, utils.PublicReadExecPermission)
		if err != nil {
			return nil, fmt.Errorf("create current directory: %w", err)
		}
	} else {
		// Move files.
		for _, file := range files {
			// Check if file is ignored.
			if slices.ContainsFunc(u.cfg.Ignore, func(name string) bool {
				return name == file.Name() || (runtime.GOOS == "windows" && strings.EqualFold(name, file.Name()))
			}) {
				continue
			}
			// ignore PurgeDirectory itself
			if strings.EqualFold(u.cfg.PurgeDirectory, filepath.Join(u.cfg.Directory, file.Name())) {
				continue
			}

			// Otherwise, move file to purge dir.
			src := filepath.Join(u.cfg.Directory, file.Name())
			dst := filepath.Join(u.cfg.PurgeDirectory, file.Name())
			err := u.moveInstalledFile(src, dst)
			if err != nil {
				return nil, fmt.Errorf("failed to move current file %s to purge dir: %w", file.Name(), err)
			}
		}
	}

	// Move the new index file into main directory.
	log.Debugf("updates/%s: installing the new version (v%s from %s)", u.cfg.Name, downloader.index.Version, downloader.index.Published)
	src := filepath.Join(u.cfg.DownloadDirectory, u.cfg.IndexFile)
	dst := filepath.Join(u.cfg.Directory, u.cfg.IndexFile)
	err = u.moveFile(src, dst, "", utils.PublicReadPermission)
	if err != nil {
		return nil, fmt.Errorf("failed to move index file to %s: %w", dst, err)
	}
	installedFiles := []string{u.cfg.IndexFile}

	// Move downloaded files to the current version folder.
	for _, artifact := range downloader.index.Artifacts {
		src = filepath.Join(u.cfg.DownloadDirectory, artifact.Filename)
		dst = filepath.Join(u.cfg.Directory, artifact.Filename)
		err = u.moveFile(src, dst, artifact.SHA256, artifact.GetFileMode())
		if err != nil {
			return installedFiles, fmt.Errorf("failed to move file %s: %w", artifact.Filename, err)
		} else {
			installedFiles = append(installedFiles, artifact.Filename)
			log.Debugf("updates/%s: %s moved", u.cfg.Name, artifact.Filename)
		}
	}

	// Set new index on module.
	u.index = downloader.index
	log.Infof("updates/%s: update complete (v%s from %s)", u.cfg.Name, u.index.Version, u.index.Published)

	return installedFiles, nil
}

// existingUpgradeTargets records actual destination entries, including dangling
// symlinks. Files absent before this attempt must not survive failed installation.
func (u *Updater) existingUpgradeTargets(index *Index) (map[string]bool, error) {
	names := []string{u.cfg.IndexFile}
	for _, artifact := range index.Artifacts {
		names = append(names, artifact.Filename)
	}
	existing := make(map[string]bool, len(names))
	for _, name := range names {
		if !filepath.IsLocal(name) || name == "." {
			return nil, fmt.Errorf("invalid upgrade target %q", name)
		}
		_, err := os.Lstat(filepath.Join(u.cfg.Directory, name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect upgrade target %s: %w", name, err)
		}
		existing[name] = err == nil
	}
	return existing, nil
}

func (u *Updater) removeIntroducedArtifacts(previousFiles map[string]bool, installedFiles []string) error {
	var cleanupErrors []error
	for _, name := range installedFiles {
		if previousFiles[name] {
			continue
		}
		// Never recursively remove a directory: unexpected contents need an
		// explicit recovery error rather than deletion of unrelated files.
		if err := os.Remove(filepath.Join(u.cfg.Directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove introduced artifact %s: %w", name, err))
		}
	}
	return errors.Join(cleanupErrors...)
}

// moveFile moves a file and falls back to copying if it fails.
func (u *Updater) moveFile(currentPath, newPath string, sha256sum string, filePermission utils.FSPermission) error {
	// Try to simply move file.
	err := os.Rename(currentPath, newPath)
	if err == nil {
		// Moving was successful, return.
		utils.SetFilePermission(newPath, filePermission)
		return nil
	}
	log.Tracef("updates/%s: failed to move to %q, falling back to copy+delete: %s", u.cfg.Name, newPath, err)

	// Copy and check the checksum while we are at it.
	err = copyAndCheckSHA256Sum(currentPath, newPath, sha256sum, filePermission)
	if err != nil {
		return fmt.Errorf("move failed, copy+delete fallback failed: %w", err)
	}

	return nil
}

// recoverFromFailedUpgrade attempts to roll back any moved files by the upgrade process.
func (u *Updater) recoverFromFailedUpgrade() error {
	// Get list of files from purge dir.
	files, err := os.ReadDir(u.cfg.PurgeDirectory)
	if err != nil {
		return err
	}

	var recoveryErrors []error
	// Move all files back to main dir, even if an individual restoration fails.
	for _, file := range files {
		purgedFile := filepath.Join(u.cfg.PurgeDirectory, file.Name())
		activeFile := filepath.Join(u.cfg.Directory, file.Name())
		err := u.moveInstalledFile(purgedFile, activeFile)
		if err != nil {
			// Only warn and continue to recover as many files as possible.
			log.Warningf("updates/%s: failed to roll back file %s: %s", u.cfg.Name, file.Name(), err)
			recoveryErrors = append(recoveryErrors, fmt.Errorf("restore %s: %w", file.Name(), err))
		}
	}

	return errors.Join(recoveryErrors...)
}

// moveInstalledFile retains the installed file's permissions during backup and
// recovery. The normal artifact installer assigns permissions for new files;
// applying those defaults to a previous installation can make it unusable.
func (u *Updater) moveInstalledFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := u.moveFile(src, dst, "", utils.PublicReadPermission); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return os.Chmod(dst, info.Mode().Perm())
	}
	return nil
}

func (u *Updater) cleanupAfterUpgrade() error {
	err := os.RemoveAll(u.cfg.PurgeDirectory)
	if err != nil {
		return fmt.Errorf("delete purge dir: %w", err)
	}

	err = os.RemoveAll(u.cfg.DownloadDirectory)
	if err != nil {
		return fmt.Errorf("delete download dir: %w", err)
	}

	return nil
}

func (u *Updater) deleteUnfinishedFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, e := range entries {
		switch {
		case e.IsDir():
			// Continue.

		case strings.HasSuffix(e.Name(), ".download"):
			path := filepath.Join(dir, e.Name())
			log.Warningf("updates/%s: deleting unfinished download file: %s", u.cfg.Name, path)
			err := os.Remove(path)
			if err != nil {
				log.Errorf("updates/%s: failed to delete unfinished download file %s: %s", u.cfg.Name, path, err)
			}

		case strings.HasSuffix(e.Name(), ".copy"):
			path := filepath.Join(dir, e.Name())
			log.Warningf("updates/%s: deleting unfinished copied file: %s", u.cfg.Name, path)
			err := os.Remove(path)
			if err != nil {
				log.Errorf("updates/%s: failed to delete unfinished copied file %s: %s", u.cfg.Name, path, err)
			}
		}
	}

	return nil
}

func (u *Updater) applyPostUpgradeCommands() error {
	// At this point, we assume that the upgrade was successful and all files are in place.
	// We need to execute the post-upgrade commands, if any.

	if len(u.cfg.PostUpgradeCommands) == 0 {
		return nil
	}

	// collect full paths to files that were upgraded, required to check the trigger.
	upgradedFiles := make(map[string]struct{})
	for _, artifact := range u.index.Artifacts {
		upgradedFiles[filepath.Join(u.cfg.Directory, artifact.Filename)] = struct{}{}
	}

	// Execute post-upgrade commands.
	for _, puCmd := range u.cfg.PostUpgradeCommands {

		// Check trigger to ensure that we need to run this command.
		if len(puCmd.TriggerArtifactFName) > 0 {
			if _, ok := upgradedFiles[puCmd.TriggerArtifactFName]; !ok {
				continue
			}
		}

		log.Debugf("updates/%s: executing post-upgrade command: '%s %s'", u.cfg.Name, puCmd.Command, strings.Join(puCmd.Args, " "))
		output, err := exec.Command(puCmd.Command, puCmd.Args...).CombinedOutput()
		if err != nil {
			if puCmd.FailOnError {
				return fmt.Errorf("post-upgrade command '%s %s' failed: %w, output: %s", puCmd.Command, strings.Join(puCmd.Args, " "), err, string(output))
			}

			log.Warningf("updates/%s: post-upgrade command '%s %s' failed, but ignored. Error: %s", u.cfg.Name, puCmd.Command, strings.Join(puCmd.Args, " "), err)
		}
	}

	return nil
}
