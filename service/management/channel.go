package management

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const controlALPN = "packettale-control/1"
const channelServerName = "agent.packettale.internal"
const maxChannelMessage = 131072

type unconfiguredManagementTransport struct{}

func (unconfiguredManagementTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("private management transport is not configured")
}

//go:embed channel_roots.json
var channelRootsJSON []byte

type ChannelTrust struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type channelManifest struct {
	Version          int    `json:"version"`
	OrganizationID   string `json:"organization_id"`
	ServerURL        string `json:"server_url"`
	CAPEM            string `json:"channel_ca_pem"`
	UpdateSigningKey string `json:"update_signing_key"`
}

func (c Config) channelManifest() (channelManifest, error) {
	var manifest channelManifest
	var roots map[string]string
	if json.Unmarshal(channelRootsJSON, &roots) != nil {
		return manifest, errors.New("invalid embedded channel trust")
	}
	key, keyErr := base64.StdEncoding.DecodeString(roots[c.ChannelTrust.KeyID])
	data, dataErr := base64.StdEncoding.DecodeString(c.ChannelTrust.Payload)
	signature, sigErr := base64.StdEncoding.DecodeString(c.ChannelTrust.Signature)
	if keyErr != nil || dataErr != nil || sigErr != nil || len(key) != ed25519.PublicKeySize || len(data) > 16384 ||
		!ed25519.Verify(key, data, signature) {
		return manifest, errors.New("untrusted organisation channel identity")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Version != 1 ||
		manifest.OrganizationID == "" || manifest.ServerURL != c.ServerURL || manifest.UpdateSigningKey != c.UpdateSigningKey {
		return manifest, errors.New("channel trust does not match the configured organisation")
	}
	return manifest, nil
}

// wsStream adapts binary WebSocket messages to the reliable ordered net.Conn
// required by crypto/tls. It contains no cryptographic implementation.
type wsStream struct {
	*websocket.Conn
	reader  io.Reader
	writeMu sync.Mutex
}

func (s *wsStream) Read(data []byte) (int, error) {
	for {
		if s.reader != nil {
			n, err := s.reader.Read(data)
			if err == io.EOF {
				s.reader = nil
				if n > 0 {
					return n, nil
				}
				continue
			}
			return n, err
		}
		kind, r, err := s.NextReader()
		if err != nil {
			return 0, err
		}
		if kind != websocket.BinaryMessage {
			return 0, errors.New("non-binary private channel frame")
		}
		s.reader = r
	}
}

func (s *wsStream) Write(data []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(data) > 0 {
		n := min(len(data), 65536)
		if err := s.WriteMessage(websocket.BinaryMessage, data[:n]); err != nil {
			return written, err
		}
		written += n
		data = data[n:]
	}
	return written, nil
}
func (s *wsStream) LocalAddr() net.Addr  { return s.UnderlyingConn().LocalAddr() }
func (s *wsStream) RemoteAddr() net.Addr { return s.UnderlyingConn().RemoteAddr() }
func (s *wsStream) SetDeadline(t time.Time) error {
	return errors.Join(s.SetReadDeadline(t), s.SetWriteDeadline(t))
}

func (c *Client) openChannel(ctx context.Context, config Config, alpn string, anonymous bool) (*tls.Conn, error) {
	manifest, err := config.channelManifest()
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(manifest.CAPEM)) {
		return nil, errors.New("invalid channel authority")
	}
	outer, err := config.tlsConfig()
	if err != nil {
		return nil, err
	}
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second, TLSClientConfig: outer}
	ws, resp, err := dialer.DialContext(ctx, "wss"+strings.TrimPrefix(config.ServerURL, "https")+"/ws/agent-channel/", nil)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		if resp != nil {
			return nil, fmt.Errorf("private channel WebSocket handshake: HTTP %d: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("private channel connection: %w", err)
	}
	ws.SetReadLimit(maxChannelMessage)
	inner := &tls.Config{RootCAs: roots, ServerName: channelServerName, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{alpn}}
	if !anonymous {
		state := c.identitySnapshot()
		if state.CertificatePEM != "" {
			certificate, e := tls.X509KeyPair([]byte(state.CertificatePEM), []byte(state.PrivateKeyPEM))
			if e != nil {
				ws.Close()
				return nil, e
			}
			inner.Certificates = []tls.Certificate{certificate}
		}
	}
	conn := tls.Client(&wsStream{Conn: ws}, inner)
	handshakeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err = conn.HandshakeContext(handshakeCtx); err != nil {
		ws.Close()
		return nil, fmt.Errorf("private channel TLS handshake: %w", err)
	}
	if conn.ConnectionState().NegotiatedProtocol != alpn {
		ws.Close()
		return nil, errors.New("private channel protocol mismatch")
	}
	if !anonymous {
		if address, ok := conn.LocalAddr().(*net.TCPAddr); ok && address.IP != nil {
			ip := address.IP.String()
			c.connectionLocalIP.Store(&ip)
		}
	}
	return conn, nil
}

func (c *Client) privateHTTPClient(config Config, anonymous bool) *http.Client {
	transport := &http.Transport{ForceAttemptHTTP2: false, MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Redirects and arbitrary portal-supplied origins must never obtain a device key.
			expected, err := http.NewRequest(http.MethodGet, config.ServerURL, nil)
			if err != nil {
				return nil, err
			}
			host := expected.URL.Host
			if expected.URL.Port() == "" {
				host = net.JoinHostPort(expected.URL.Hostname(), "443")
			}
			if address != host {
				return nil, errors.New("private channel origin mismatch")
			}
			return c.openChannel(ctx, config, "http/1.1", anonymous)
		}}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: noManagementRedirect}
}

type privateControl struct {
	*tls.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
}

func (c *privateControl) WriteJSON(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > maxChannelMessage {
		return errors.New("control message too large")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	_, err = c.Write(append(prefix[:], data...))
	return err
}
func (c *privateControl) ReadMessage() (int, []byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(c.reader, prefix[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 || size > maxChannelMessage {
		return 0, nil, errors.New("invalid control message size")
	}
	data := make([]byte, size)
	_, err := io.ReadFull(c.reader, data)
	return 0, data, err
}

func newDeviceKey() (string, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
func deviceCSR(keyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return "", errors.New("invalid device private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}
