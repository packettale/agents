package management

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

var channelTestSigner = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, 32))

func init() {
	var roots map[string]string
	if err := json.Unmarshal(channelRootsJSON, &roots); err != nil {
		panic(err)
	}
	roots["unit-test-only"] = base64.StdEncoding.EncodeToString(channelTestSigner.Public().(ed25519.PublicKey))
	channelRootsJSON, _ = json.Marshal(roots)
}

type channelFixture struct {
	Config         Config
	CA             *x509.Certificate
	Key            ed25519.PrivateKey
	Captured       bytes.Buffer
	ReadCiphertext bytes.Buffer
	mu             sync.Mutex
	Control        func(*privateControl)
	Groups         []tls.CurveID
	CorruptWrites  atomic.Bool
	OuterStatus    atomic.Int32
}

type recordedChannel struct {
	net.Conn
	fixture *channelFixture
}

func (c *recordedChannel) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	c.fixture.mu.Lock()
	c.fixture.Captured.Write(data[:n])
	c.fixture.ReadCiphertext.Write(data[:n])
	c.fixture.mu.Unlock()
	return n, err
}
func (c *recordedChannel) Write(data []byte) (int, error) {
	c.fixture.mu.Lock()
	c.fixture.Captured.Write(data)
	c.fixture.mu.Unlock()
	if c.fixture.CorruptWrites.Load() && len(data) > 5 {
		data = bytes.Clone(data)
		data[len(data)-1] ^= 1
	}
	return c.Conn.Write(data)
}

func (f *channelFixture) identity(t *testing.T, id, credential string) State {
	t.Helper()
	key, err := newDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(key))
	parsed, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	return State{DeviceID: id, Credential: credential, PrivateKeyPEM: key, KeyCreatedAt: time.Now().UTC(), CertificatePEM: f.certificate(t, parsed.(ed25519.PrivateKey).Public(), id, false)}
}

// Existing domain tests use ordinary WebSocket peers. This test-only bridge
// keeps those assertions while the client always uses the new private channel.
func bridgeControlFixture(t *testing.T, server *httptest.Server, control *privateControl) {
	t.Helper()
	_, auth, err := control.ReadMessage()
	if err != nil {
		return
	}
	var identity map[string]string
	if json.Unmarshal(auth, &identity) != nil {
		return
	}
	dialer := websocket.Dialer{TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig}
	upstream, _, err := dialer.Dial("wss"+strings.TrimPrefix(server.URL, "https")+"/ws/device/", http.Header{"Authorization": {"Bearer " + identity["credential"]}})
	if err != nil {
		return
	}
	defer upstream.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer control.Close()
		for {
			_, data, e := upstream.ReadMessage()
			if e != nil {
				return
			}
			var value any
			if json.Unmarshal(data, &value) != nil {
				return
			}
			if object, ok := value.(map[string]any); ok && object["type"] == "policy" {
				object["server_time"] = time.Now().UTC().Format(time.RFC3339Nano)
			}
			if control.WriteJSON(value) != nil {
				return
			}
		}
	}()
	for {
		_, data, e := control.ReadMessage()
		if e != nil {
			break
		}
		if upstream.WriteMessage(websocket.TextMessage, data) != nil {
			break
		}
	}
	upstream.Close()
	control.Close()
	<-done
}

func (f *channelFixture) certificate(t testing.TB, key any, name string, server bool) string {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		template.DNSNames = []string{channelServerName}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.CA, key, f.Key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func testChannelServer(t testing.TB, handler http.Handler) *channelFixture {
	t.Helper()
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test authority"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, public, key)
	ca, _ := x509.ParseCertificate(der)
	f := &channelFixture{CA: ca, Key: key, Groups: []tls.CurveID{tls.X25519MLKEM768}}
	serverKey, _ := newDeviceKey()
	block, _ := pem.Decode([]byte(serverKey))
	parsed, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	certPEM := f.certificate(t, parsed.(ed25519.PrivateKey).Public(), channelServerName, true)
	serverPair, _ := tls.X509KeyPair([]byte(certPEM), []byte(serverKey))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws/agent-channel/" || r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
			t.Error("secret or invalid route on outer connection")
			return
		}
		if status := f.OuterStatus.Load(); status != 0 {
			w.Header().Set("X-Private-Test", "must-not-appear-in-diagnostics")
			http.Error(w, "must-not-appear-in-diagnostics", int(status))
			return
		}
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		conn := tls.Server(&recordedChannel{Conn: &wsStream{Conn: ws}, fixture: f}, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, NextProtos: []string{controlALPN, "http/1.1"}, CurvePreferences: f.Groups})
		defer conn.Close()
		if conn.Handshake() != nil {
			return
		}
		if conn.ConnectionState().NegotiatedProtocol == controlALPN {
			if f.Control != nil {
				f.Control(&privateControl{Conn: conn, reader: bufio.NewReader(conn)})
			}
			return
		}
		reader := bufio.NewReader(conn)
		for {
			request, e := http.ReadRequest(reader)
			if e != nil {
				return
			}
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, request)
			request.Body.Close()
			response := result.Result()
			response.ContentLength = int64(result.Body.Len())
			if response.Write(conn) != nil {
				return
			}
			response.Body.Close()
		}
	}))
	t.Cleanup(server.Close)
	manifest := channelManifest{Version: 1, OrganizationID: "test", ServerURL: server.URL, CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	payload, _ := json.Marshal(manifest)
	f.Config = Config{ServerURL: server.URL, EnrollmentToken: "one-time-token", Name: "test-host", Platform: "linux",
		CACertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
		ChannelTrust:     ChannelTrust{KeyID: "unit-test-only", Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(channelTestSigner, payload))}}
	return f
}

func TestDeviceCertificateBindsProvisionedOrganisationAndDevice(t *testing.T) {
	f := testChannelServer(t, http.NotFoundHandler())
	manifest, err := f.Config.channelManifest()
	if err != nil {
		t.Fatal(err)
	}
	manifest.OrganizationID = "orgc05ae900d300420d8b93b161869d54ee"
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	f.Config.ChannelTrust.Payload = base64.StdEncoding.EncodeToString(payload)
	f.Config.ChannelTrust.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(channelTestSigner, payload))
	state := f.identity(t, "c05ae900-d300-420d-8b93-b161869d54ee", "credential")
	if err := validateDeviceCertificate(f.Config, state); err != nil {
		t.Fatal(err)
	}
	wrongDevice := state
	wrongDevice.DeviceID = "f05ae900-d300-420d-8b93-b161869d54ee"
	if validateDeviceCertificate(f.Config, wrongDevice) == nil {
		t.Fatal("wrong device certificate accepted")
	}
	other := testChannelServer(t, http.NotFoundHandler())
	foreign := other.identity(t, state.DeviceID, state.Credential)
	if validateDeviceCertificate(f.Config, foreign) == nil {
		t.Fatal("certificate from another organisation authority accepted")
	}
	wrongKey := state
	wrongKey.PrivateKeyPEM = foreign.PrivateKeyPEM
	if validateDeviceCertificate(f.Config, wrongKey) == nil {
		t.Fatal("certificate with mismatched private key accepted")
	}
}

func TestChannelTrustRejectsSubstitution(t *testing.T) {
	f := testChannelServer(t, http.NotFoundHandler())
	if err := f.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){func(c *Config) { c.ServerURL = "https://other.example" }, func(c *Config) { c.ChannelTrust.Payload += "x" }, func(c *Config) { c.ChannelTrust.KeyID = "unknown" }, func(c *Config) { c.UpdateSigningKey = "substituted" }} {
		c := f.Config
		change(&c)
		if c.Validate() == nil {
			t.Fatal("substituted channel trust accepted")
		}
	}
}

func TestPrivateChannelLive(t *testing.T) {
	path := os.Getenv("PACKETTALE_CHANNEL_TEST_CONFIG")
	if path == "" {
		t.Skip("requires disposable real portal")
	}
	recoveryOptions(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = writePrivateBytes(filepath.Join(dir, configFile), data); err != nil {
		t.Fatal(err)
	}
	c := New(dir, nil)
	config, err := c.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = c.enroll(ctx, config); err != nil {
		t.Fatal(err)
	}
	if err = c.loadState(); err != nil {
		t.Fatal(err)
	}
	if err = validateDeviceCertificate(config, c.identitySnapshot()); err != nil {
		t.Fatal(err)
	}
	response, err := c.httpClient.Get(config.ServerURL + "/api/v1/device/policy/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing credential response %d", response.StatusCode)
	}
	if err = c.recoverPolicy(ctx, config); err != nil {
		t.Fatal(err)
	}
	before := c.identitySnapshot()
	if err = c.renewCertificate(ctx, config, true); err != nil {
		t.Fatal(err)
	}
	if before.PrivateKeyPEM == c.identitySnapshot().PrivateKeyPEM {
		t.Fatal("key did not rotate")
	}
	if err = c.renewCertificate(ctx, config, false); err != nil {
		t.Fatal(err)
	}
	conn, err := c.openChannel(ctx, config, controlALPN, false)
	if err != nil {
		t.Fatal(err)
	}
	if ip := c.connectionLocalIP.Load(); ip == nil || *ip != conn.LocalAddr().(*net.TCPAddr).IP.String() {
		t.Fatal("authenticated channel did not record its real local source")
	}
	control := &privateControl{Conn: conn, reader: bufio.NewReader(conn)}
	defer conn.Close()
	if err = control.WriteJSON(map[string]string{"credential": c.identitySnapshot().Credential}); err != nil {
		t.Fatal(err)
	}
	_, message, err := control.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(message, []byte(`"type":"policy"`)) && !bytes.Contains(message, []byte(`"type": "policy"`)) {
		t.Fatal("policy not delivered inside TLS")
	}
	if err = control.WriteJSON(map[string]string{"type": "ping"}); err != nil {
		t.Fatal(err)
	}
	_, message, err = control.ReadMessage()
	if err != nil || !bytes.Contains(message, []byte("pong")) {
		t.Fatalf("heartbeat failed: %v", err)
	}
	t.Log("Go/Python hybrid TLS enrollment, HTTP, key rotation, renewal, control policy and heartbeat passed")
	if output := os.Getenv("PACKETTALE_CHANNEL_TEST_DEVICE_ID_FILE"); output != "" {
		if err = os.WriteFile(output, []byte(c.identitySnapshot().DeviceID), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrivateHTTPDoesNotExposeCredentialToOuterHandler(t *testing.T) {
	var observed string
	f := testChannelServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = r.Header.Get("Authorization")
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("protected reply"))
	}))
	c := New(t.TempDir(), nil)
	client := c.privateHTTPClient(f.Config, true)
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodPost, f.Config.ServerURL+"/api/v1/enroll/", strings.NewReader("private enrollment content"))
	req.Header.Set("Authorization", "Bearer private-sentinel")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if observed != "Bearer private-sentinel" {
		t.Fatal("inner credentials not delivered")
	}
	data, _ := io.ReadAll(response.Body)
	if string(data) != "protected reply" {
		t.Fatal("inner response mismatch")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, secret := range []string{"private-sentinel", "private enrollment content", "protected reply"} {
		if bytes.Contains(f.Captured.Bytes(), []byte(secret)) {
			t.Fatal("plaintext content visible outside inner TLS")
		}
	}
}

func TestPrivateChannelRefusesClassicalOnlyServer(t *testing.T) {
	f := testChannelServer(t, http.NotFoundHandler())
	f.Groups = []tls.CurveID{tls.X25519}
	c := New(t.TempDir(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := c.openChannel(ctx, f.Config, "http/1.1", true); err == nil {
		conn.Close()
		t.Fatal("classical-only key exchange accepted")
	}
}

func TestPrivateChannelRejectsTamperedTLSRecords(t *testing.T) {
	var f *channelFixture
	f = testChannelServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.CorruptWrites.Store(true)
		w.Write([]byte("must-not-be-accepted"))
	}))
	c := New(t.TempDir(), nil)
	client := c.privateHTTPClient(f.Config, true)
	defer client.CloseIdleConnections()
	response, err := client.Get(f.Config.ServerURL + "/api/v1/device/policy/")
	if err == nil {
		defer response.Body.Close()
		if _, err = io.ReadAll(response.Body); err == nil {
			t.Fatal("tampered TLS record was accepted")
		}
	}
}

func TestPrivateChannelRejectsReplayedRecordOnFreshConnection(t *testing.T) {
	var requests atomic.Int32
	f := testChannelServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write([]byte("reply")) }))
	c := New(t.TempDir(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := c.openChannel(ctx, f.Config, "http/1.1", true)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	req, _ := http.NewRequest(http.MethodGet, f.Config.ServerURL+"/api/v1/device/policy/", nil)
	if err = req.Write(first); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(first), req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	f.mu.Lock()
	captured := bytes.Clone(f.ReadCiphertext.Bytes())
	f.mu.Unlock()
	var replay []byte
	for len(captured) >= 5 {
		size := int(binary.BigEndian.Uint16(captured[3:5])) + 5
		if size > len(captured) {
			t.Fatal("incomplete captured TLS record")
		}
		if captured[0] == 23 {
			replay = bytes.Clone(captured[:size])
		}
		captured = captured[size:]
	}
	if replay == nil {
		t.Fatal("no encrypted record captured")
	}
	second, err := c.openChannel(ctx, f.Config, "http/1.1", true)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err = second.NetConn().Write(replay); err != nil {
		t.Fatal(err)
	}
	second.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, err = second.Read(data[:]); err == nil {
		t.Fatal("replayed record accepted")
	}
	if value, ok := err.(net.Error); ok && value.Timeout() {
		t.Fatal("replayed record was not actively rejected")
	}
	if requests.Load() != 1 {
		t.Fatal("replayed request reached application")
	}
}

func TestPrivateChannelRejectsUnsignedConfigurationBeforeNetwork(t *testing.T) {
	config := Config{ServerURL: "https://127.0.0.1:1"}
	c := New(t.TempDir(), nil)
	if _, err := c.openChannel(context.Background(), config, "http/1.1", true); err == nil {
		t.Fatal("unsigned identity accepted")
	}
}

// Opt-in measurements use the same disposable Python consumer/database for
// baseline WSS and protected WSS+TLS. They are qualification, not an SLA.
func TestPrivateChannelPerformance(t *testing.T) {
	path := os.Getenv("PACKETTALE_CHANNEL_BENCH_CONFIG")
	if path == "" {
		t.Skip("requires explicit performance qualification portal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c := New(t.TempDir(), nil)
	var cfg Config
	if json.Unmarshal(data, &cfg) != nil {
		t.Fatal("invalid qualification config")
	}
	c.httpClient = c.privateHTTPClient(cfg, false)
	if err = c.enroll(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	type sample struct {
		Mode         string  `json:"mode"`
		P50          float64 `json:"p50_ms"`
		P95          float64 `json:"p95_ms"`
		P99          float64 `json:"p99_ms"`
		HandshakeP50 float64 `json:"handshake_p50_ms"`
		Count        int     `json:"count"`
	}
	var results []sample
	for _, secure := range []bool{false, true} {
		latencies := make([]float64, 0, 300)
		handshakes := make([]float64, 0, 20)
		for attempt := 0; attempt < 20; attempt++ {
			start := time.Now()
			var read func() (int, []byte, error)
			var write func(any) error
			var close func() error
			if secure {
				conn, e := c.openChannel(context.Background(), cfg, controlALPN, false)
				if e != nil {
					t.Fatal(e)
				}
				control := &privateControl{Conn: conn, reader: bufio.NewReader(conn)}
				read = control.ReadMessage
				write = control.WriteJSON
				close = control.Close
				if e = write(map[string]string{"credential": c.identitySnapshot().Credential}); e != nil {
					t.Fatal(e)
				}
			} else {
				outer, _ := cfg.tlsConfig()
				dialer := websocket.Dialer{TLSClientConfig: outer}
				conn, _, e := dialer.Dial("wss"+strings.TrimPrefix(cfg.ServerURL, "https")+"/qa/control/", http.Header{"Authorization": {"Bearer " + c.identitySnapshot().Credential}})
				if e != nil {
					t.Fatal(e)
				}
				read = conn.ReadMessage
				write = conn.WriteJSON
				close = conn.Close
			}
			if _, _, e := read(); e != nil {
				close()
				t.Fatal(e)
			}
			handshakes = append(handshakes, float64(time.Since(start).Nanoseconds())/1e6)
			if attempt == 19 {
				for i := 0; i < 300; i++ {
					start := time.Now()
					if e := write(map[string]string{"type": "ping"}); e != nil {
						t.Fatal(e)
					}
					if _, _, e := read(); e != nil {
						t.Fatal(e)
					}
					latencies = append(latencies, float64(time.Since(start).Nanoseconds())/1e6)
				}
			}
			close()
		}
		sort.Float64s(latencies)
		sort.Float64s(handshakes)
		mode := "ordinary_wss"
		if secure {
			mode = "wss_plus_hybrid_tls"
		}
		results = append(results, sample{Mode: mode, P50: latencies[150], P95: latencies[284], P99: latencies[296], HandshakeP50: handshakes[9], Count: len(latencies)})
	}
	encoded, _ := json.MarshalIndent(results, "", "  ")
	if output := os.Getenv("PACKETTALE_CHANNEL_BENCH_OUTPUT"); output != "" {
		if err = os.WriteFile(output, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(string(encoded))
}

func TestPrivateChannelOfflineExpiryAndRevocation(t *testing.T) {
	path := os.Getenv("PACKETTALE_CHANNEL_LIFECYCLE_CONFIG")
	if path == "" {
		t.Skip("requires explicit lifecycle qualification portal")
	}
	recoveryOptions(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if json.Unmarshal(data, &cfg) != nil {
		t.Fatal("invalid lifecycle config")
	}
	c := New(t.TempDir(), nil)
	c.httpClient = c.privateHTTPClient(cfg, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = c.enroll(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	request := func(path string, body []byte) (*http.Response, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ServerURL+path, bytes.NewReader(body))
		if e != nil {
			return nil, e
		}
		req.Header.Set("Authorization", "Bearer "+c.identitySnapshot().Credential)
		req.Header.Set("Content-Type", "application/json")
		return c.httpClient.Do(req)
	}
	state := c.identitySnapshot()
	csr, _ := deviceCSR(state.PrivateKeyPEM)
	body, _ := json.Marshal(map[string]string{"csr": csr})
	response, err := request("/api/v1/device/qa-expired-certificate/", body)
	if err != nil {
		t.Fatal(err)
	}
	var expired struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if json.NewDecoder(response.Body).Decode(&expired) != nil || expired.CertificatePEM == "" {
		t.Fatal("expiry fixture failed")
	}
	response.Body.Close()
	state.CertificatePEM = expired.CertificatePEM
	if err = c.saveIdentity(state); err != nil {
		t.Fatal(err)
	}
	c.httpClient.CloseIdleConnections()
	if err = c.renewCertificate(ctx, cfg, false); err != nil {
		t.Fatal("offline expired identity did not renew:", err)
	}
	if err = validateDeviceCertificate(cfg, c.identitySnapshot()); err != nil {
		t.Fatal(err)
	}
	if err = c.recoverPolicy(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	conn, err := c.openChannel(ctx, cfg, controlALPN, false)
	if err != nil {
		t.Fatal(err)
	}
	control := &privateControl{Conn: conn, reader: bufio.NewReader(conn)}
	defer control.Close()
	control.WriteJSON(map[string]string{"credential": state.Credential})
	if _, _, err = control.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	response, err = request("/api/v1/device/qa-revoke/", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("revocation fixture failed")
	}
	control.SetReadDeadline(time.Now().Add(5 * time.Second))
	control.WriteJSON(map[string]string{"type": "ping"})
	if _, _, err = control.ReadMessage(); err == nil {
		t.Fatal("revoked live channel accepted another heartbeat")
	}
	if err = c.renewCertificate(ctx, cfg, false); err == nil {
		t.Fatal("revoked identity renewed")
	}
	if err = c.enroll(ctx, cfg); err == nil {
		t.Fatal("revoked key reactivated through enrollment")
	}
	if MandatoryHistoryDays() == 0 {
		t.Fatal("revocation discarded cached firewall policy")
	}
	t.Log("expired/offline certificate renewed; active socket, renewal and reenrollment rejected after revocation")
}

func TestPrivateChannelUploadPerformance(t *testing.T) {
	path := os.Getenv("PACKETTALE_CHANNEL_UPLOAD_CONFIG")
	if path == "" {
		t.Skip("requires explicit upload qualification portal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if json.Unmarshal(data, &cfg) != nil {
		t.Fatal("invalid qualification config")
	}
	c := New(t.TempDir(), nil)
	c.httpClient = c.privateHTTPClient(cfg, false)
	if err = c.enroll(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	outer, _ := cfg.tlsConfig()
	baseline := &http.Client{Transport: &http.Transport{TLSClientConfig: outer}, Timeout: 30 * time.Second}
	defer baseline.CloseIdleConnections()
	defer c.httpClient.CloseIdleConnections()
	payload := bytes.Repeat([]byte{0x61}, 1024*1024)
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	type resourceSample struct {
		User   float64 `json:"user_seconds"`
		System float64 `json:"system_seconds"`
		RSS    int     `json:"max_rss_kib"`
	}
	type result struct {
		Mode         string  `json:"mode"`
		MiBPerSecond float64 `json:"mib_per_second"`
		UserCPU      float64 `json:"server_user_seconds"`
		SystemCPU    float64 `json:"server_system_seconds"`
		RSS          int     `json:"server_max_rss_kib"`
		Bytes        int     `json:"uploaded_bytes"`
	}
	var results []result
	for _, secure := range []bool{false, true} {
		client := baseline
		prefix := "/qa/"
		mode := "ordinary_https"
		if secure {
			client = c.httpClient
			prefix = "/api/v1/device/qa-"
			mode = "wss_plus_hybrid_tls"
		}
		getMetrics := func() resourceSample {
			request, _ := http.NewRequest(http.MethodGet, cfg.ServerURL+prefix+"metrics/", nil)
			request.Header.Set("Authorization", "Bearer "+c.identitySnapshot().Credential)
			response, e := client.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			var value resourceSample
			if json.NewDecoder(response.Body).Decode(&value) != nil {
				t.Fatal("resource metrics unavailable")
			}
			return value
		}
		before := getMetrics()
		start := time.Now()
		for i := 0; i < 20; i++ {
			request, _ := http.NewRequest(http.MethodPost, cfg.ServerURL+prefix+"upload/", bytes.NewReader(payload))
			request.Header.Set("Authorization", "Bearer "+c.identitySnapshot().Credential)
			request.Header.Set("Content-Type", "application/octet-stream")
			response, e := client.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			var body struct {
				Size   int    `json:"size"`
				SHA256 string `json:"sha256"`
			}
			e = json.NewDecoder(response.Body).Decode(&body)
			response.Body.Close()
			if e != nil || response.StatusCode != 200 || body.Size != len(payload) || body.SHA256 != digest {
				t.Fatalf("streaming upload failed: HTTP %d, %v", response.StatusCode, e)
			}
		}
		elapsed := time.Since(start).Seconds()
		after := getMetrics()
		results = append(results, result{Mode: mode, MiBPerSecond: 20 / elapsed, UserCPU: after.User - before.User, SystemCPU: after.System - before.System, RSS: after.RSS, Bytes: 20 * len(payload)})
	}
	encoded, _ := json.MarshalIndent(results, "", "  ")
	if output := os.Getenv("PACKETTALE_CHANNEL_UPLOAD_OUTPUT"); output != "" {
		os.WriteFile(output, encoded, 0600)
	}
	t.Log(string(encoded))
}

func TestPrivateChannelDownloadStreaming(t *testing.T) {
	path := os.Getenv("PACKETTALE_CHANNEL_DOWNLOAD_CONFIG")
	if path == "" {
		t.Skip("requires explicit streaming qualification portal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if json.Unmarshal(data, &cfg) != nil {
		t.Fatal("invalid qualification config")
	}
	directory := t.TempDir()
	c := New(directory, nil)
	c.httpClient = c.privateHTTPClient(cfg, false)
	if err = c.enroll(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	metrics := func() map[string]any {
		req, _ := http.NewRequest(http.MethodGet, cfg.ServerURL+"/api/v1/device/qa-metrics/", nil)
		req.Header.Set("Authorization", "Bearer "+c.identitySnapshot().Credential)
		response, e := c.httpClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		value := map[string]any{}
		if e = json.NewDecoder(response.Body).Decode(&value); e != nil {
			t.Fatal(e)
		}
		return value
	}
	before := metrics()
	digest := fmt.Sprintf("%x", sha256.Sum256(make([]byte, 32*1024*1024)))
	start := time.Now()
	destination := filepath.Join(directory, "artifact")
	if err = c.fetchReleaseArtifact(context.Background(), cfg.ServerURL+"/api/v1/device/qa-download/", destination, digest, c.identitySnapshot().Credential); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(destination)
	if err != nil || stat.Size() != 32*1024*1024 {
		t.Fatal("download length mismatch")
	}
	after := metrics()
	result := map[string]any{"before": before, "after": after, "bytes": stat.Size(), "seconds": time.Since(start).Seconds()}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	if output := os.Getenv("PACKETTALE_CHANNEL_DOWNLOAD_OUTPUT"); output != "" {
		os.WriteFile(output, encoded, 0600)
	}
	t.Log(string(encoded))
}

func TestPrivateChannelLocalSourceUsesConnectedSocket(t *testing.T) {
	f := testChannelServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	c := New(t.TempDir(), nil)
	c.state = f.identity(t, "source-test", "source-credential")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	anonymous, err := c.openChannel(ctx, f.Config, "http/1.1", true)
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Close()
	if c.connectionLocalIP.Load() != nil {
		t.Fatal("anonymous channel changed device address")
	}
	conn, err := c.openChannel(ctx, f.Config, "http/1.1", false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if ip := c.connectionLocalIP.Load(); ip == nil || *ip != conn.LocalAddr().(*net.TCPAddr).IP.String() {
		t.Fatal("source does not match actual connected socket")
	}
}

func TestChannelConnectionFailureDiagnostics(t *testing.T) {
	f := testChannelServer(t, http.NotFoundHandler())
	c := New(t.TempDir(), nil)
	for _, status := range []int{403, 429, 502} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f.OuterStatus.Store(int32(status))
			conn, err := c.openChannel(context.Background(), f.Config, controlALPN, true)
			if conn != nil || !errors.Is(err, websocket.ErrBadHandshake) || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", status)) {
				t.Fatalf("missing HTTP status or original cause: %v", err)
			}
			if strings.Contains(err.Error(), "must-not-appear") {
				t.Fatal("response contents leaked")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.openChannel(ctx, f.Config, controlALPN, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation cause: %v", err)
	}
}

func TestPrivateChannelEnrollmentClockLive(t *testing.T) {
	path := os.Getenv("PACKETTALE_CLOCK_TEST_CONFIG")
	if path == "" {
		t.Skip("requires disposable real portal invitation")
	}
	recoveryOptions(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := writePrivateBytes(filepath.Join(dir, configFile), data); err != nil {
		t.Fatal(err)
	}
	c := New(dir, nil)
	cfg, err := c.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	key, err := newDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := deviceCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	client := c.privateHTTPClient(cfg, true)
	defer client.CloseIdleConnections()
	for _, offset := range []time.Duration{5 * time.Hour, -5 * time.Hour} {
		body, err := json.Marshal(map[string]string{"token": cfg.EnrollmentToken, "name": cfg.Name, "platform": cfg.Platform, "version": "1.0.0", "credential": strings.Repeat("x", 64), "csr": csr, "client_time": time.Now().Add(offset).UTC().Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ServerURL+"/api/v1/enroll/", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var failure struct {
			Code string `json:"code"`
		}
		err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&failure)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest || err != nil || failure.Code != "device_clock" {
			t.Fatalf("clock rejection: status=%d code=%q error=%v", response.StatusCode, failure.Code, err)
		}
	}
	if err := c.enroll(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	state := c.identitySnapshot()
	if state.DeviceID == "" {
		t.Fatal("valid-time retry did not enroll")
	}
	t.Logf("LIVE_CLOCK_PROOF device=%s negative_offsets=+5h,-5h invitation_max_uses=1 valid_time_enrolled=true", state.DeviceID)
}
