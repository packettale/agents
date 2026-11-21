package updates

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safing/jess"
)

// newSigningKey generates a key and a trust store that holds its public half.
func newSigningKey(t *testing.T, name string) (signet *jess.Signet, trustStore *jess.MemTrustStore) {
	t.Helper()

	signet, err := jess.GenerateSignet("Ed25519", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := signet.AssignUUID(); err != nil {
		t.Fatal(err)
	}
	signet.Info = &jess.SignetInfo{Name: name}
	// Serialize the key into the signet; an envelope treats a signet
	// without serialized key as a reference into a trust store.
	if err := signet.StoreKey(); err != nil {
		t.Fatal(err)
	}

	rcpt, err := signet.AsRecipient()
	if err != nil {
		t.Fatal(err)
	}
	trustStore = jess.NewMemTrustStore()
	if err := trustStore.StoreSignet(rcpt); err != nil {
		t.Fatal(err)
	}
	return signet, trustStore
}

// TestParseIndexVerifiesSignature checks that ParseIndex, given a trust
// store, accepts exactly the index signed with a trusted key: a signature
// from another key, no signature, and a change after signing all fail.
func TestParseIndexVerifiesSignature(t *testing.T) {
	t.Parallel()

	key, trustStore := newSigningKey(t, "test key")
	_, otherTrustStore := newSigningKey(t, "other key")

	dir := t.TempDir()
	if err := GenerateMockFolder(dir, "Test", "1.0.0", time.Now()); err != nil {
		t.Fatal(err)
	}
	index, err := LoadIndex(filepath.Join(dir, "index.json"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := index.Export(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := index.Export(key, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseIndex(signed, "", trustStore); err != nil {
		t.Errorf("signed index must verify: %s", err)
	}
	if _, err := ParseIndex(signed, "", otherTrustStore); err == nil {
		t.Error("index signed with an unknown key must fail")
	}
	if _, err := ParseIndex(unsigned, "", trustStore); err == nil {
		t.Error("unsigned index must fail")
	}
	tampered := bytes.Replace(signed, []byte(`"Test"`), []byte(`"Tampered"`), 1)
	if bytes.Equal(tampered, signed) {
		t.Fatal("test did not tamper with the index")
	}
	if _, err := ParseIndex(tampered, "", trustStore); err == nil {
		t.Error("tampered index must fail")
	}
}

// Download and install must preserve the signed bytes so a service restart
// re-verifies the same manifest rather than accepting a directory scan.
func TestSignedDownloadPreservesManifestAfterRestart(t *testing.T) {
	key, trust := newSigningKey(t, "download key")
	origin := t.TempDir()
	if err := GenerateMockFolder(origin, "Test", "1.0.1", time.Now()); err != nil {
		t.Fatal(err)
	}
	index, err := LoadIndex(filepath.Join(origin, "index.json"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.FileServer(http.Dir(origin)))
	defer server.Close()
	for _, artifact := range index.Artifacts {
		artifact.URLs = []string{server.URL + "/" + artifact.Filename}
	}
	signed, err := index.Export(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origin, "index.json"), signed, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Name: "Test", Directory: t.TempDir(), DownloadDirectory: t.TempDir(), PurgeDirectory: t.TempDir(), IndexFile: "index.json", Verify: trust}
	updater, err := New(nil, "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The test transport is loopback HTTP; production configuration remains HTTPS-only.
	updater.cfg.IndexURLs = []string{server.URL + "/index.json"}
	if err := updater.ForceUpdateContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(filepath.Join(cfg.Directory, cfg.IndexFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persisted, signed) {
		t.Fatal("download changed signed manifest")
	}
	restarted, err := New(nil, "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.corruptedInstallation != nil {
		t.Fatalf("restart rejected verified manifest: %v", restarted.corruptedInstallation)
	}
	if restarted.index == nil || restarted.index.Version != "1.0.1" {
		t.Fatal("restart did not load signed index")
	}
	restarted.cfg.IndexURLs = []string{server.URL + "/index.json"}
	// An unsigned network replacement must not replace the installed signed index.
	unsigned, err := index.Export(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origin, "index.json"), unsigned, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ForceUpdateContext(context.Background()); err == nil {
		t.Fatal("unsigned network replacement accepted")
	}
	persisted, err = os.ReadFile(filepath.Join(cfg.Directory, cfg.IndexFile))
	if err != nil || !bytes.Equal(persisted, signed) {
		t.Fatal("rejected network index changed installed manifest")
	}
}
