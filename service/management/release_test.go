package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/packettale/agents/base/info"
	"github.com/packettale/agents/service/configure"
	"github.com/packettale/agents/service/updates"
	"github.com/safing/jess"
)

func TestUpdateTrustAcceptsOnlyProvisionedEd25519Recipient(t *testing.T) {
	key, err := jess.GenerateSignet("Ed25519", 0)
	if err != nil {
		t.Fatal(err)
	}
	key.ID = "release-test"
	publicText, err := key.Export(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "garbage", string(make([]byte, 4097))} {
		if _, err := (Config{UpdateSigningKey: invalid}).UpdateTrust(); err == nil {
			t.Fatal("invalid release key was accepted")
		}
	}
	trust, err := (Config{UpdateSigningKey: publicText}).UpdateTrust()
	if err != nil {
		t.Fatal(err)
	}
	index := &updates.Index{ManagementProtocol: 1, Name: configure.DefaultBinaryIndexName, Version: "1.0.1"}
	privateTrust := jess.NewMemTrustStore()
	if err := privateTrust.StoreSignet(key); err != nil {
		t.Fatal(err)
	}
	public, err := key.AsRecipient()
	if err != nil {
		t.Fatal(err)
	}
	if err := privateTrust.StoreSignet(public); err != nil {
		t.Fatal(err)
	}
	signed, err := index.Export(key, privateTrust)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := updates.ParseIndex(signed, "linux_amd64", trust); err != nil {
		t.Fatalf("provisioned key did not verify signed index: %v", err)
	}
}

func TestSameVersionReleaseVerifiesSignatureAndEveryArtifact(t *testing.T) {
	key, err := jess.GenerateSignet("Ed25519", 0)
	if err != nil {
		t.Fatal(err)
	}
	key.ID = "release-test"
	publicText, err := key.Export(true)
	if err != nil {
		t.Fatal(err)
	}
	releaseID := uuid.NewString()
	platform := runtime.GOOS + "_" + runtime.GOARCH
	files := make(map[string][]byte)
	var signed []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer endpoint-credential" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/index/") {
			_, _ = w.Write(signed)
			return
		}
		data, ok := files[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	baseURL := server.URL + "/api/v1/releases/" + releaseID + "/"
	index := &updates.Index{ManagementProtocol: 1, Name: configure.DefaultBinaryIndexName, Version: info.VersionNumber(), Published: time.Now()}
	for _, name := range requiredBinaryFiles[platform] {
		data := []byte("signed-" + name)
		path := baseURL + "files/" + platform + "/" + name
		files[strings.TrimPrefix(path, server.URL)] = data
		hash := sha256.Sum256(data)
		index.Artifacts = append(index.Artifacts, &updates.Artifact{Filename: name, Platform: platform,
			SHA256: hex.EncodeToString(hash[:]), URLs: []string{path}})
	}
	trust := jess.NewMemTrustStore()
	if err := trust.StoreSignet(key); err != nil {
		t.Fatal(err)
	}
	public, err := key.AsRecipient()
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.StoreSignet(public); err != nil {
		t.Fatal(err)
	}
	signed, err = index.Export(key, trust)
	if err != nil {
		t.Fatal(err)
	}
	client := New(t.TempDir(), nil)
	client.httpClient = server.Client()
	client.httpClient.CheckRedirect = noManagementRedirect
	cfg := Config{ServerURL: server.URL, UpdateSigningKey: publicText}
	if err := client.stageRelease(t.Context(), cfg, "endpoint-credential", releaseID, info.VersionNumber()); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(client.dataDir, "download_binaries")
	for _, name := range requiredBinaryFiles[platform] {
		data, err := os.ReadFile(filepath.Join(staged, name))
		if err != nil || string(data) != "signed-"+name {
			t.Fatalf("artifact %s was not staged correctly: %v", name, err)
		}
	}
	firstURL := baseURL + "files/" + platform + "/" + requiredBinaryFiles[platform][0]
	firstPath := strings.TrimPrefix(firstURL, server.URL)
	original := files[firstPath]
	files[firstPath] = []byte("tampered")
	if err := client.stageRelease(t.Context(), cfg, "endpoint-credential", releaseID, info.VersionNumber()); err == nil {
		t.Fatal("tampered artifact should not stage")
	}
	files[firstPath] = original
	approvedIndex := signed
	index.ManagementProtocol = 0
	signed, err = index.Export(key, trust)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.stageRelease(t.Context(), cfg, "endpoint-credential", releaseID, info.VersionNumber()); err == nil || !strings.Contains(err.Error(), "private agent channel") {
		t.Fatal("validly signed pre-channel agent was accepted as an update")
	}
	index.ManagementProtocol = 1
	signed = approvedIndex
	if err := os.Remove(filepath.Join(staged, "index.json")); err != nil {
		t.Fatal(err)
	}
	signed[len(signed)/2] ^= 1
	if err := client.stageRelease(t.Context(), cfg, "endpoint-credential", releaseID, info.VersionNumber()); err == nil {
		t.Fatal("tampered index should not stage")
	}
}

func TestReleaseArtifactHasItsOwnTimeoutAndRetainsTransportSecurity(t *testing.T) {
	payload := []byte("verified artifact")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-download-credential" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		time.Sleep(80 * time.Millisecond)
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	client := New(t.TempDir(), nil)
	client.httpClient = server.Client()
	client.httpClient.Timeout = 20 * time.Millisecond
	client.httpClient.CheckRedirect = noManagementRedirect
	sum := sha256.Sum256(payload)
	target := filepath.Join(client.dataDir, "core")
	if err := client.fetchReleaseArtifact(t.Context(), server.URL, target, hex.EncodeToString(sum[:]), "test-download-credential"); err != nil {
		t.Fatalf("download inherited management deadline: %v", err)
	}
	if client.httpClient.Timeout != 20*time.Millisecond {
		t.Fatal("management deadline was modified")
	}
	if _, err := client.fetchReleaseIndex(t.Context(), server.URL, "test-download-credential"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("index should retain the short management deadline: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := client.fetchReleaseArtifact(ctx, server.URL, target+"-cancelled", hex.EncodeToString(sum[:]), "test-download-credential"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("download ignored caller deadline: %v", err)
	}
	if err := client.fetchReleaseArtifact(t.Context(), server.URL, target+"-unauthorized", hex.EncodeToString(sum[:]), "wrong"); err == nil {
		t.Fatal("download did not enforce authorization")
	}
}

func TestUpdateStagingReasonReportsFailureWithinPortalLimit(t *testing.T) {
	if actual := updateStagingReason(fmt.Errorf("download: %w", context.DeadlineExceeded)); !strings.Contains(actual, "timed out") {
		t.Fatalf("unhelpful timeout: %s", actual)
	}
	if actual := updateStagingReason(errors.New("release server returned HTTP 403")); !strings.Contains(actual, "HTTP 403") {
		t.Fatalf("missing HTTP status: %s", actual)
	}
	private := updateStagingReason(errors.New("open C:\\ProgramData\\PacketTale\\private.json: access denied"))
	if strings.Contains(private, "private.json") || strings.Contains(private, "ProgramData") {
		t.Fatal("update reason exposed an internal path")
	}
	actual := updateStagingReason(errors.New(strings.Repeat("界\n", 300)))
	if len([]rune(actual)) > 255 || strings.ContainsAny(actual, "\n\r") {
		t.Fatal("failure reason exceeds portal bounds")
	}
}

func TestStageReleaseRefusesDowngradeBeforeDownload(t *testing.T) {
	client := New(t.TempDir(), nil)
	if err := client.stageRelease(t.Context(), Config{}, "", uuid.NewString(), "0.0.0"); err == nil || !strings.Contains(err.Error(), "must not be older") {
		t.Fatalf("downgrade accepted or failed for wrong reason: %v", err)
	}
}
