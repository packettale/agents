package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/service/configure"
	"github.com/packettale/agents/service/management"
	"github.com/packettale/agents/service/updates"
	"github.com/safing/jess"
)

type ServiceConfig struct {
	BinDir  string
	DataDir string

	LogToStdout bool
	LogDir      string
	LogLevel    string

	BinariesIndexURLs   []string
	IntelIndexURLs      []string
	VerifyBinaryUpdates jess.TrustStore
	VerifyIntelUpdates  jess.TrustStore
}

func (sc *ServiceConfig) Init() error {
	// Check directories.
	switch runtime.GOOS {
	case "windows":
		// Fall back to defaults.
		if sc.BinDir == "" {
			exeDir, err := getCurrentBinaryFolder() // Default: C:/Program Files/packettale
			if err != nil {
				return fmt.Errorf("derive bin dir from running exe: %w", err)
			}
			sc.BinDir = exeDir
		}
		if sc.DataDir == "" {
			sc.DataDir = filepath.FromSlash("$ProgramData/packettale")
		}
		if sc.LogDir == "" {
			sc.LogDir = filepath.Join(sc.DataDir, "logs")
		}

	case "linux":
		// Fall back to defaults.
		if sc.BinDir == "" {
			sc.BinDir = "/usr/lib/packettale"
		}
		if sc.DataDir == "" {
			sc.DataDir = "/var/lib/packettale"
		}
		if sc.LogDir == "" {
			sc.LogDir = "/var/log/packettale"
		}

	default:
		// Fail if not configured on other platforms.
		if sc.BinDir == "" {
			return errors.New("binary directory must be configured - auto-detection not supported on this platform")
		}
		if sc.DataDir == "" {
			return errors.New("binary directory must be configured - auto-detection not supported on this platform")
		}
		if !sc.LogToStdout && sc.LogDir == "" {
			return errors.New("logging directory must be configured - auto-detection not supported on this platform")
		}
	}

	// Expand path variables.
	sc.BinDir = os.ExpandEnv(sc.BinDir)
	sc.DataDir = os.ExpandEnv(sc.DataDir)
	sc.LogDir = os.ExpandEnv(sc.LogDir)

	// Apply defaults for required fields.
	if len(sc.BinariesIndexURLs) == 0 {
		sc.BinariesIndexURLs = configure.DefaultStableBinaryIndexURLs
	}
	if len(sc.IntelIndexURLs) == 0 {
		sc.IntelIndexURLs = configure.DefaultIntelIndexURLs
	}

	// Check log level.
	if sc.LogLevel != "" && log.ParseLevel(sc.LogLevel) == 0 {
		return fmt.Errorf("invalid log level %q", sc.LogLevel)
	}

	return nil
}

// returns the absolute path of the currently running executable
func getCurrentBinaryPath() (string, error) {
	// Get the path of the currently running executable
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	// Get the absolute path
	absPath, err := filepath.Abs(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	return absPath, nil
}

func getCurrentBinaryFolder() (string, error) {
	// Get the absolute path of the currently running executable
	absPath, err := getCurrentBinaryPath()
	if err != nil {
		return "", err
	}

	// Get the directory of the executable
	installDir := filepath.Dir(absPath)

	return installDir, nil
}

func MakeUpdateConfigs(svcCfg *ServiceConfig) (binaryUpdateConfig, intelUpdateConfig *updates.Config, err error) {
	intelTrust := svcCfg.VerifyIntelUpdates
	if intelTrust == nil {
		intelTrust = configure.IntelSigningTrustStore
	}
	binaryTrust := svcCfg.VerifyBinaryUpdates
	if data, readErr := os.ReadFile(filepath.Join(svcCfg.DataDir, "management.json")); readErr == nil {
		var managed management.Config
		if json.Unmarshal(data, &managed) == nil && managed.UpdateSigningKey != "" {
			if trust, trustErr := managed.UpdateTrust(); trustErr == nil {
				binaryTrust = trust
			} else {
				log.Warningf("enterprise: software update key is invalid; managed binary updates disabled: %s", trustErr)
			}
		}
	}
	switch runtime.GOOS {
	case "windows":
		binaryUpdateConfig = &updates.Config{
			Name:              configure.DefaultBinaryIndexName,
			Directory:         svcCfg.BinDir,
			DownloadDirectory: filepath.Join(svcCfg.DataDir, "download_binaries"),
			PurgeDirectory:    filepath.Join(svcCfg.BinDir, "upgrade_obsolete_binaries"),
			Ignore:            []string{"uninstall.exe", "purge-data.ps1", "LICENSE.txt"}, // "databases", "intel" and "config.json" not needed here since they are not in the bin dir.
			IndexURLs:         nil,                                                        // Enterprise software updates must come from the management server.
			IndexFile:         "index.json",
			Verify:            binaryTrust,
			AutoCheck:         false,
			AutoDownload:      false,
			AutoApply:         false,
			NeedsRestart:      true,
			Notify:            false, // Managed updates restart in the background after applying.
		}
		intelUpdateConfig = &updates.Config{
			Name:              configure.DefaultIntelIndexName,
			Directory:         filepath.Join(svcCfg.DataDir, "intel"),
			DownloadDirectory: filepath.Join(svcCfg.DataDir, "download_intel"),
			PurgeDirectory:    filepath.Join(svcCfg.DataDir, "upgrade_obsolete_intel"),
			IndexURLs:         svcCfg.IntelIndexURLs,
			IndexFile:         "index.json",
			Verify:            intelTrust,
			AutoCheck:         true, // May be changed by config during instance startup.
			AutoDownload:      true,
			AutoApply:         true,
			NeedsRestart:      false,
			Notify:            false,
		}

	case "linux":
		binaryUpdateConfig = &updates.Config{
			Name:              configure.DefaultBinaryIndexName,
			Directory:         svcCfg.BinDir,
			DownloadDirectory: filepath.Join(svcCfg.DataDir, "download_binaries"),
			PurgeDirectory:    filepath.Join(svcCfg.DataDir, "upgrade_obsolete_binaries"),
			Ignore:            []string{"management.json.template"}, // Do not delete enrollment templates during a binary update.
			IndexURLs:         nil,                                  // Enterprise software updates must come from the management server.
			IndexFile:         "index.json",
			Verify:            binaryTrust,
			AutoCheck:         false,
			AutoDownload:      false,
			AutoApply:         false,
			NeedsRestart:      true,
			Notify:            false, // Managed updates restart in the background after applying.
		}
		if binPath, err := getCurrentBinaryPath(); err == nil {
			binaryUpdateConfig.PostUpgradeCommands = []updates.UpdateCommandConfig{
				// Restore SELinux context for the new core binary after upgrade
				// (`restorecon /usr/lib/packettale/packettale-core`)
				{
					Command:              "restorecon",
					Args:                 []string{binPath},
					TriggerArtifactFName: binPath,
					FailOnError:          false, // Ignore error: 'restorecon' may not be available on a non-SELinux systems.
				},
			}
		} else {
			return nil, nil, fmt.Errorf("failed to get current binary path: %w", err)
		}

		intelUpdateConfig = &updates.Config{
			Name:              configure.DefaultIntelIndexName,
			Directory:         filepath.Join(svcCfg.DataDir, "intel"),
			DownloadDirectory: filepath.Join(svcCfg.DataDir, "download_intel"),
			PurgeDirectory:    filepath.Join(svcCfg.DataDir, "upgrade_obsolete_intel"),
			IndexURLs:         svcCfg.IntelIndexURLs,
			IndexFile:         "index.json",
			Verify:            intelTrust,
			AutoCheck:         true, // May be changed by config during instance startup.
			AutoDownload:      true,
			AutoApply:         true,
			NeedsRestart:      false,
			Notify:            false,
		}
	}

	return
}
