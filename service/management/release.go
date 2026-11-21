package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	semver "github.com/hashicorp/go-version"
	"github.com/packettale/agents/base/info"
	"github.com/packettale/agents/service/configure"
	"github.com/packettale/agents/service/updates"
)

const maxIndexBytes = 256 << 10
const maxArtifactBytes = 150 << 20
const releaseArtifactTimeout = 5 * time.Minute

var requiredBinaryFiles = map[string][]string{
	"linux_amd64": {"packettale-core"},
	"windows_amd64": {"packettale-core.exe", "packettale-core.dll",
		"packettale-kext.sys"},
}

func (c *Client) stageRelease(ctx context.Context, cfg Config, credential, releaseID, version string) error {
	parsedID, err := uuid.Parse(releaseID)
	if err != nil || parsedID.String() != releaseID {
		return errors.New("invalid release ID")
	}
	targetVersion, err := semver.NewVersion(version)
	if err != nil {
		return errors.New("invalid target version")
	}
	currentVersion, err := semver.NewVersion(info.VersionNumber())
	if err != nil || targetVersion.LessThan(currentVersion) {
		return errors.New("release version must not be older than the installed core")
	}
	trust, err := cfg.UpdateTrust()
	if err != nil {
		return err
	}
	platform := runtime.GOOS + "_" + runtime.GOARCH
	expected, supported := requiredBinaryFiles[platform]
	if !supported {
		return errors.New("unsupported update platform")
	}
	baseURL := cfg.ServerURL + "/api/v1/releases/" + releaseID + "/"
	indexData, err := c.fetchReleaseIndex(ctx, baseURL+"index/", credential)
	if err != nil {
		return err
	}
	index, err := updates.ParseIndex(indexData, platform, trust)
	if err != nil {
		return fmt.Errorf("release signature failed: %w", err)
	}
	if err := index.CanDoUpgrades(); err != nil {
		return fmt.Errorf("invalid release publication: %w", err)
	}
	if err := validateReleaseIndex(index, version, platform, baseURL+"files/", expected); err != nil {
		return err
	}
	downloadDir := filepath.Join(c.dataDir, "download_binaries")
	if err := os.RemoveAll(downloadDir); err != nil {
		return err
	}
	if err := os.MkdirAll(downloadDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(downloadDir, "index.json"), indexData, 0o600); err != nil {
		return err
	}
	for _, artifact := range index.Artifacts {
		if err := c.fetchReleaseArtifact(ctx, artifact.URLs[0], filepath.Join(downloadDir, artifact.Filename), artifact.SHA256, credential); err != nil {
			return fmt.Errorf("stage %s: %w", artifact.Filename, err)
		}
	}
	return nil
}

func validateReleaseIndex(index *updates.Index, version, platform, filesURL string, expected []string) error {
	if index.ManagementProtocol != 1 {
		return errors.New("release does not support the required private agent channel")
	}
	if index.Name != configure.DefaultBinaryIndexName || index.Version != version ||
		len(index.Artifacts) != len(expected) {
		return errors.New("release does not contain the complete platform package")
	}
	wanted := make(map[string]bool, len(expected))
	for _, name := range expected {
		wanted[name] = true
	}
	for _, artifact := range index.Artifacts {
		if artifact.Platform != platform || !wanted[artifact.Filename] || artifact.Unpack != "" ||
			len(artifact.URLs) != 1 || artifact.URLs[0] != filesURL+artifact.Platform+"/"+artifact.Filename {
			return errors.New("release contains an unexpected artifact or download URL")
		}
		if len(artifact.SHA256) != sha256.Size*2 {
			return errors.New("release artifact has an invalid checksum")
		}
		wanted[artifact.Filename] = false
	}
	for _, missing := range wanted {
		if missing {
			return errors.New("release is missing a platform artifact")
		}
	}
	return nil
}

func authorizedReleaseRequest(ctx context.Context, client *http.Client, url, credential string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("release server returned HTTP %d", response.StatusCode)
	}
	return response, nil
}

func (c *Client) fetchReleaseIndex(ctx context.Context, url, credential string) ([]byte, error) {
	response, err := authorizedReleaseRequest(ctx, c.httpClient, url, credential)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxIndexBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read release index: %w", err)
	}
	if len(data) > maxIndexBytes {
		return nil, errors.New("release index exceeds size limit")
	}
	return data, nil
}

func (c *Client) fetchReleaseArtifact(ctx context.Context, url, path, expectedHash, credential string) error {
	// Binary transfers can exceed the short timeout used for management API calls.
	// Copy the client so its TLS, redirect and transport settings are preserved.
	downloadClient := *c.httpClient
	downloadClient.Timeout = releaseArtifactTimeout
	response, err := authorizedReleaseRequest(ctx, &downloadClient, url, credential)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	file, err := os.OpenFile(path+".part", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := setPrivateFilePermissions(file); err != nil {
		file.Close()
		return err
	}
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maxArtifactBytes+1))
	if err == nil && (size == 0 || size > maxArtifactBytes || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expectedHash)) {
		err = errors.New("release artifact is too large, empty, or has a checksum mismatch")
	}
	if syncErr := file.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(path+".part", path)
}

// updateStagingReason exposes the actionable failure without credentials or a
// portal-supplied command. Download URLs have fixed paths and no secret query.
func updateStagingReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "Release download timed out. Check endpoint connectivity and retry."
	}
	message := err.Error()
	if at := strings.Index(message, "HTTP "); at >= 0 && len(message) >= at+8 {
		code := message[at+5 : at+8]
		if code[0] >= '1' && code[0] <= '5' && code[1] >= '0' && code[1] <= '9' && code[2] >= '0' && code[2] <= '9' {
			return "Update download failed (HTTP " + code + "). Check connectivity and retry."
		}
	}
	if strings.Contains(message, "signature") || strings.Contains(message, "checksum") || strings.Contains(message, "digest") {
		return "Update verification failed. Retry the update or contact your administrator."
	}
	return "Unable to prepare the update. Retry or contact your administrator."

}
