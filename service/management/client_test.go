package management

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/base/info"
)

func TestConfigRejectsInsecureServer(t *testing.T) {
	for _, url := range []string{"http://example.org", "https://user:pass@example.org", "https://example.org/path"} {
		if err := (Config{ServerURL: url}).Validate(); err == nil {
			t.Errorf("accepted %q", url)
		}
	}
}

func TestEnrollmentPersistsCredentialWithoutInvitation(t *testing.T) {
	var fixture *channelFixture
	fixture = testChannelServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll/" || r.Method != http.MethodPost {
			t.Error("invalid enrollment route")
		}
		var request map[string]string
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid enrollment")
		}
		if request["version"] != info.VersionNumber() {
			t.Error("missing running version")
		}
		stamp, clockErr := time.Parse(time.RFC3339Nano, request["client_time"])
		if clockErr != nil || time.Since(stamp) > time.Minute || time.Until(stamp) > time.Minute {
			t.Error("missing current device time")
		}
		block, _ := pem.Decode([]byte(request["csr"]))
		if block == nil {
			t.Error("missing CSR")
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Error("invalid CSR proof")
			return
		}
		certificate := fixture.certificate(t, csr.PublicKey, "dev-1", false)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"device_id": "dev-1", "certificate_pem": certificate})
	}))
	dir := t.TempDir()
	client := New(dir, nil)
	cfg := fixture.Config
	if err := writePrivateJSON(filepath.Join(dir, configFile), cfg); err != nil {
		t.Fatal(err)
	}
	if err := client.enroll(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	state, err := readIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if state.DeviceID != "dev-1" || state.PrivateKeyPEM == "" || state.CertificatePEM == "" || len(state.Credential) != 64 {
		t.Fatal("identity not persisted")
	}
	data, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil || bytes.Contains(data, []byte("one-time-token")) {
		t.Fatal("invitation not cleared")
	}
	if runtime.GOOS != "windows" {
		file, _ := os.Stat(filepath.Join(dir, stateFile))
		if file.Mode().Perm() != 0600 {
			t.Fatal("identity permissions")
		}
	}
}

func TestInvalidManagementConfigDoesNotStopPackettale(t *testing.T) {
	defer config.SetLocalWritesLocked(false)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(`{"server_url":"http://insecure.test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := New(dir, nil).Start(); err != nil {
		t.Fatalf("management config stopped service startup: %v", err)
	}
	if !config.LocalWritesLocked() {
		t.Fatal("management configuration did not lock local writes before policy sync")
	}
}

func TestCustomCAEnablesPrivateControl(t *testing.T) {
	connected := make(chan struct{}, 1)
	f := testChannelServer(t, http.NotFoundHandler())
	f.Control = func(control *privateControl) {
		_, _, err := control.ReadMessage()
		if err == nil {
			connected <- struct{}{}
		}
	}
	c := New(t.TempDir(), nil)
	c.state = f.identity(t, "test-device", "test-credential")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = c.connect(ctx, f.Config)
	select {
	case <-connected:
	default:
		t.Fatal("private control did not trust configured outer CA and signed inner identity")
	}
}

func TestInvalidCustomCAIsRejected(t *testing.T) {
	var config Config
	if err := json.Unmarshal([]byte(`{"server_url":"https://example.org","ca_certificate_pem":"not a certificate"}`), &config); err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(); err == nil {
		t.Fatal("invalid custom CA was accepted")
	}
}

func TestEnrollmentDoesNotFollowRedirectWithInvitation(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := New(t.TempDir(), nil)
	client.httpClient = server.Client()
	_ = client.enroll(context.Background(), Config{ServerURL: server.URL, EnrollmentToken: "test-invitation"})
	if redirected {
		t.Fatal("enrollment invitation was sent to a redirected server")
	}
}

func TestEnrollmentClockRejectionPreservesIdentityAndInvitation(t *testing.T) {
	f := testChannelServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"device_clock","error":"untrusted response text"}`))
	}))
	dir := t.TempDir()
	c := New(dir, nil)
	if err := writePrivateJSON(filepath.Join(dir, configFile), f.Config); err != nil {
		t.Fatal(err)
	}
	err := c.enroll(context.Background(), f.Config)
	if err == nil || !strings.Contains(err.Error(), "synchronize the device date and time") || strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("unexpected clock error: %v", err)
	}
	state, err := readIdentity(dir)
	if err != nil || state.DeviceID != "" || state.Credential == "" {
		t.Fatal("clock rejection consumed or lost device identity")
	}
	cfg, err := c.loadConfig()
	if err != nil || cfg.EnrollmentToken != f.Config.EnrollmentToken {
		t.Fatal("clock rejection consumed invitation")
	}
}
