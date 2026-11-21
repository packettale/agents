package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/packettale/agents/service/updates"
	"github.com/safing/jess"
)

func TestReleaseIndexRequiresCompletePlatformPackages(t *testing.T) {
	root := t.TempDir()
	if _, err := buildIndex(root, "1.0.1", "https://example.test/releases/one/files"); err == nil {
		t.Fatal("empty release should be rejected")
	}
	for platform, names := range requiredFiles {
		if err := os.Mkdir(filepath.Join(root, platform), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(root, platform, name), []byte(platform+name), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := buildIndex(root, "1.0.1", "http://example.test/releases/one/files"); err == nil {
		t.Fatal("plaintext release URL should be rejected")
	}
	index, err := buildIndex(root, "1.0.1", "https://example.test/releases/one/files")
	if err != nil {
		t.Fatal(err)
	}
	for platform, names := range requiredFiles {
		if count := countPlatform(index, platform); count != len(names) {
			t.Fatalf("%s: got %d artifacts, want %d", platform, count, len(names))
		}
	}
	if err := os.Remove(filepath.Join(root, "windows_amd64", "packettale-core.exe")); err != nil {
		t.Fatal(err)
	}
	if _, err := buildIndex(root, "1.0.1", "https://example.test/releases/one/files"); err == nil {
		t.Fatal("incomplete Windows package should be rejected")
	}
}

func TestReleaseIndexSignature(t *testing.T) {
	root := t.TempDir()
	for platform, names := range requiredFiles {
		if err := os.Mkdir(filepath.Join(root, platform), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(root, platform, name), []byte(name), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	index, err := buildIndex(root, "1.0.1", "https://example.test/releases/one/files")
	if err != nil {
		t.Fatal(err)
	}
	key, err := jess.GenerateSignet("Ed25519", 0)
	if err != nil {
		t.Fatal(err)
	}
	key.ID = "test-packettale-release"
	data, err := signIndex(index, key)
	if err != nil {
		t.Fatal(err)
	}
	publicText, err := key.Export(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyRelease(root, publicText); err != nil {
		t.Fatalf("complete signed release should verify: %v", err)
	}
	trust := jess.NewMemTrustStore()
	public, err := key.AsRecipient()
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.StoreSignet(public); err != nil {
		t.Fatal(err)
	}
	if _, err := updates.ParseIndex(data, "linux_amd64", trust); err != nil {
		t.Fatalf("signed release did not verify: %v", err)
	}
	data[len(data)/2] ^= 1
	if _, err := updates.ParseIndex(data, "linux_amd64", trust); err == nil {
		t.Fatal("tampered release should not verify")
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyRelease(root, publicText); err == nil {
		t.Fatal("tampered release directory should not verify")
	}
}
