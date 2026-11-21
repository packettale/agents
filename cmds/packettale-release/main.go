// packettale-release creates complete, signed Windows and Linux binary indexes.
// Keep the private key outside source control and the management server.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	semver "github.com/hashicorp/go-version"
	"github.com/packettale/agents/service/configure"
	"github.com/packettale/agents/service/updates"
	"github.com/safing/jess"
)

var requiredFiles = map[string][]string{
	"linux_amd64": {"packettale-core"},
	"windows_amd64": {"packettale-core.exe", "packettale-core.dll",
		"packettale-kext.sys"},
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: packettale-release keygen | sign | verify")
	}
	switch args[0] {
	case "keygen":
		flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
		privatePath := flags.String("private", "", "private key output path")
		publicPath := flags.String("public", "", "public key output path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *privatePath == "" || *publicPath == "" || flags.NArg() != 0 {
			return errors.New("keygen requires -private and -public")
		}
		key, err := jess.GenerateSignet("Ed25519", 0)
		if err != nil {
			return err
		}
		key.ID = "packettale-release-1"
		privateText, err := key.Backup(true)
		if err != nil {
			return err
		}
		publicText, err := key.Export(true)
		if err != nil {
			return err
		}
		if err := writeExclusive(*privatePath, []byte(privateText+"\n"), 0o600); err != nil {
			return err
		}
		if err := writeExclusive(*publicPath, []byte(publicText+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Printf("Created release keys. Keep %s private; provision %s with managed endpoint installers.\n", *privatePath, *publicPath)
		return nil
	case "sign":
		flags := flag.NewFlagSet("sign", flag.ContinueOnError)
		root := flags.String("dir", "", "directory with linux_amd64 and windows_amd64 subdirectories")
		version := flags.String("version", "", "release version")
		baseURL := flags.String("base-url", "", "HTTPS URL for the files directory")
		privatePath := flags.String("private", "", "private signing key path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *root == "" || *version == "" || *baseURL == "" || *privatePath == "" || flags.NArg() != 0 {
			return errors.New("sign requires -dir, -version, -base-url, and -private")
		}
		index, err := buildIndex(*root, *version, *baseURL)
		if err != nil {
			return err
		}
		keyText, err := os.ReadFile(*privatePath)
		if err != nil {
			return err
		}
		key, err := jess.SenderFromTextFormat(strings.TrimSpace(string(keyText)))
		if err != nil {
			return err
		}
		if key.Scheme != "Ed25519" || key.ID == "" {
			return errors.New("release signing key must be an identified Ed25519 key")
		}
		data, err := signIndex(index, key)
		if err != nil {
			return err
		}
		if err := writeExclusive(filepath.Join(*root, "index.json"), data, 0o644); err != nil {
			return err
		}
		fmt.Printf("Signed complete %s release (%d artifacts).\n", *version, len(index.Artifacts))
		return nil
	case "verify":
		flags := flag.NewFlagSet("verify", flag.ContinueOnError)
		root := flags.String("dir", "", "directory with signed index and platform files")
		publicPath := flags.String("public", "", "public signing key path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *root == "" || *publicPath == "" || flags.NArg() != 0 {
			return errors.New("verify requires -dir and -public")
		}
		data, err := os.ReadFile(*publicPath)
		if err != nil {
			return err
		}
		if err := verifyRelease(*root, strings.TrimSpace(string(data))); err != nil {
			return err
		}
		fmt.Println("Release signature, platform packages, and artifact checksums verified.")
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func verifyRelease(root, publicKey string) error {
	recipient, err := jess.RecipientFromTextFormat(publicKey)
	if err != nil || recipient.Scheme != "Ed25519" || !recipient.Public || recipient.ID == "" {
		return errors.New("invalid Ed25519 release public key")
	}
	trust := jess.NewMemTrustStore()
	if err := trust.StoreSignet(recipient); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil || len(data) > 256<<10 {
		return errors.New("release index is missing or too large")
	}
	for platform, expected := range requiredFiles {
		index, err := updates.ParseIndex(data, platform, trust)
		if err != nil {
			return fmt.Errorf("verify signed index: %w", err)
		}
		if index.Name != configure.DefaultBinaryIndexName || index.CanDoUpgrades() != nil || len(index.Artifacts) != len(expected) {
			return fmt.Errorf("%s release index is incomplete or invalid", platform)
		}
		seen := make(map[string]bool, len(expected))
		for _, artifact := range index.Artifacts {
			if artifact.Platform != platform || artifact.Unpack != "" || seen[artifact.Filename] ||
				!contains(expected, artifact.Filename) {
				return fmt.Errorf("%s contains an unexpected artifact", platform)
			}
			seen[artifact.Filename] = true
			path := filepath.Join(root, platform, artifact.Filename)
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			fileInfo, err := file.Stat()
			if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Size() == 0 || fileInfo.Size() > updates.MaxUnpackSize {
				file.Close()
				return fmt.Errorf("invalid release file %s", path)
			}
			hash := sha256.New()
			_, err = io.Copy(hash, file)
			file.Close()
			if err != nil || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), artifact.SHA256) {
				return fmt.Errorf("release file checksum failed: %s", path)
			}
		}
		entries, err := os.ReadDir(filepath.Join(root, platform))
		if err != nil || len(entries) != len(expected) {
			return fmt.Errorf("%s directory contains unexpected files", platform)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != len(requiredFiles)+1 {
		return errors.New("release root contains unexpected files")
	}
	return nil
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func buildIndex(root, version, baseURL string) (*updates.Index, error) {
	if _, err := semver.NewVersion(version); err != nil {
		return nil, fmt.Errorf("invalid release version: %w", err)
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("release files URL must be an HTTPS URL without credentials or query")
	}
	rootEntries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	if len(rootEntries) != len(requiredFiles) {
		return nil, errors.New("release directory must contain only linux_amd64 and windows_amd64")
	}
	index := &updates.Index{Name: configure.DefaultBinaryIndexName, Version: version, ManagementProtocol: 1,
		Published: time.Now().UTC(), Artifacts: make([]*updates.Artifact, 0, 11)}
	for _, platform := range []string{"linux_amd64", "windows_amd64"} {
		path := filepath.Join(root, platform)
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		expected := requiredFiles[platform]
		if len(entries) != len(expected) {
			return nil, fmt.Errorf("%s requires exactly %d files", platform, len(expected))
		}
		found := make(map[string]bool, len(expected))
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				return nil, fmt.Errorf("%s/%s must be a regular file", platform, entry.Name())
			}
			found[entry.Name()] = true
		}
		for _, name := range expected {
			if !found[name] {
				return nil, fmt.Errorf("%s is missing %s", platform, name)
			}
			file, err := os.Open(filepath.Join(path, name))
			if err != nil {
				return nil, err
			}
			stat, err := file.Stat()
			if err != nil || stat.Size() == 0 || stat.Size() > updates.MaxUnpackSize {
				file.Close()
				return nil, fmt.Errorf("%s/%s has invalid size", platform, name)
			}
			hash := sha256.New()
			_, err = io.Copy(hash, file)
			file.Close()
			if err != nil {
				return nil, err
			}
			index.Artifacts = append(index.Artifacts, &updates.Artifact{Filename: name, Platform: platform,
				SHA256: hex.EncodeToString(hash.Sum(nil)),
				URLs:   []string{strings.TrimRight(baseURL, "/") + "/" + platform + "/" + name}})
		}
	}
	sort.Slice(index.Artifacts, func(i, j int) bool {
		if index.Artifacts[i].Platform != index.Artifacts[j].Platform {
			return index.Artifacts[i].Platform < index.Artifacts[j].Platform
		}
		return index.Artifacts[i].Filename < index.Artifacts[j].Filename
	})
	return index, nil
}

func signIndex(index *updates.Index, key *jess.Signet) ([]byte, error) {
	trust := jess.NewMemTrustStore()
	if err := trust.StoreSignet(key); err != nil {
		return nil, err
	}
	public, err := key.AsRecipient()
	if err != nil {
		return nil, err
	}
	if err := trust.StoreSignet(public); err != nil {
		return nil, err
	}
	return index.Export(key, trust)
}

func countPlatform(index *updates.Index, platform string) int {
	count := 0
	for _, artifact := range index.Artifacts {
		if artifact.Platform == platform {
			count++
		}
	}
	return count
}
