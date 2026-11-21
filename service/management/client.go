// Package enterprise adds optional outbound management to the packettale core.
// Firewall checks read only an in-memory policy snapshot; no server request is
// made on the packet or DNS processing path.
package management

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/base/info"
	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/netquery/orm"
	"github.com/packettale/agents/service/profile"
	"github.com/packettale/agents/service/updates"
	"github.com/safing/jess"
)

const configFile = "management.json"
const stateFile = "management-state.json"
const policyFile = "management-policy.json"

type Config struct {
	ChannelTrust     ChannelTrust `json:"channel_trust"`
	ServerURL        string       `json:"server_url"`
	EnrollmentToken  string       `json:"enrollment_token"`
	CACertificatePEM string       `json:"ca_certificate_pem,omitempty"`
	UpdateSigningKey string       `json:"update_signing_key,omitempty"`
	Name             string       `json:"name"`
	Platform         string       `json:"platform"`
}

// UpdateTrust returns the locally provisioned release key. The portal may
// publish releases, but it cannot change this trust anchor over the wire.
func (c Config) UpdateTrust() (jess.TrustStore, error) {
	if c.UpdateSigningKey == "" {
		return nil, errors.New("no enterprise update signing key is provisioned")
	}
	if len(c.UpdateSigningKey) > 4096 {
		return nil, errors.New("enterprise update signing key is too large")
	}
	recipient, err := jess.RecipientFromTextFormat(c.UpdateSigningKey)
	if err != nil || recipient.Scheme != "Ed25519" || !recipient.Public || recipient.ID == "" {
		return nil, errors.New("enterprise update signing key is invalid")
	}
	trust := jess.NewMemTrustStore()
	if err := trust.StoreSignet(recipient); err != nil {
		return nil, err
	}
	return trust, nil
}

func (c Config) Validate() error {
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("management server must be an HTTPS origin without credentials or path")
	}
	_, err = c.tlsConfig()
	if err != nil {
		return err
	}
	_, err = c.channelManifest()
	return err
}

func (c Config) tlsConfig() (*tls.Config, error) {
	if c.CACertificatePEM == "" {
		return nil, nil
	}
	if len(c.CACertificatePEM) > 65536 {
		return nil, errors.New("management CA certificate is too large")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(c.CACertificatePEM)) {
		return nil, errors.New("management CA certificate is invalid")
	}
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
}

type State struct {
	DeviceID       string    `json:"device_id"`
	Credential     string    `json:"credential"`
	CertificatePEM string    `json:"certificate_pem"`
	PrivateKeyPEM  string    `json:"private_key_pem"`
	KeyCreatedAt   time.Time `json:"key_created_at"`
	PendingKeyPEM  string    `json:"pending_key_pem,omitempty"`
}

type Policy struct {
	NetworkProfiles       []NetworkProfile          `json:"network_profiles,omitempty"`
	Capabilities          []string                  `json:"capabilities,omitempty"`
	Type                  string                    `json:"type"`
	Revision              int                       `json:"revision"`
	LocalHistoryDays      int                       `json:"local_history_days"`
	MandatoryBlockDomains []string                  `json:"mandatory_block_domains"`
	LockLocalChanges      bool                      `json:"lock_local_changes"`
	GlobalSettings        map[string]any            `json:"global_settings,omitempty"`
	ApplicationRules      map[string]map[string]any `json:"application_rules,omitempty"`
}

var mandatoryHistoryDays atomic.Int64
var mandatoryDomains atomic.Pointer[domainBlockPolicy]
var managedPolicyMu sync.Mutex
var activeGlobalSettings = make(map[string]any)

var allowedGlobalSettings = map[string]struct{}{
	"filter/defaultAction":          {},
	"filter/blockInternet":          {},
	"filter/blockLAN":               {},
	"filter/blockLocal":             {},
	"filter/blockP2P":               {},
	"filter/blockInbound":           {},
	"filter/endpoints":              {},
	"filter/serviceEndpoints":       {},
	"filter/lists":                  {},
	"filter/includeSubdomains":      {},
	"filter/includeCNAMEs":          {},
	"filter/removeOutOfScopeDNS":    {},
	"filter/removeBlockedDNS":       {},
	"filter/domainHeuristics":       {},
	"filter/preventBypassing":       {},
	"filter/disableAutoPermit":      {},
	"dns/nameservers":               {},
	"filter/customListFile":         {},
	"filter/dnsQueryInterception":   {},
	"filter/enable":                 {},
	"filter/permanentVerdicts":      {},
	"dns/dontResolveSpecialDomains": {},
	"dns/listenAddress":             {},
	"dns/nameserverRetryRate":       {},
	"dns/noAssignedNameservers":     {},
	"dns/followSystemRouting":       {},
	"dns/noInsecureProtocols":       {},
	"dns/noMulticastDNS":            {},
	"dns/useStaleCache":             {},
	"splittun/enable":               {},
	"splittun/use":                  {},
	"splittun/networkInterface":     {},
	"splittun/usagePolicy":          {},
	"history/enable":                {},
}

type domainBlockPolicy struct{ domains []string }

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func normalizeBlockDomains(domains []string) ([]string, error) {
	if len(domains) > 100 {
		return nil, errors.New("too many mandatory block domains")
	}
	normalized := make([]string, 0, len(domains))
	for _, raw := range domains {
		value := strings.ToLower(strings.TrimSuffix(raw, "."))
		bare := strings.TrimPrefix(value, ".")
		labels := strings.Split(bare, ".")
		if len(value) > 253 || len(labels) < 2 || value == "" {
			return nil, errors.New("invalid mandatory block domain")
		}
		for _, label := range labels {
			if !domainLabel.MatchString(label) {
				return nil, errors.New("invalid mandatory block domain")
			}
		}
		normalized = append(normalized, value)
	}
	return normalized, nil
}

// MandatoryBlockDomain checks the last valid, cached policy without a network call.
// A leading dot in a policy entry includes both the apex and subdomains.
func MandatoryBlockDomain(domain string) bool {
	policy := mandatoryDomains.Load()
	if policy == nil {
		return false
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, entry := range policy.domains {
		if domain == strings.TrimPrefix(entry, ".") {
			return true
		}
		if strings.HasPrefix(entry, ".") && strings.HasSuffix(domain, entry) {
			return true
		}
	}
	return false
}

func validateMandatoryPolicy(policy Policy) ([]string, error) {
	if policy.Revision < 1 || policy.LocalHistoryDays < 1 || policy.LocalHistoryDays > 3650 {
		return nil, errors.New("invalid management policy")
	}
	domains, err := normalizeBlockDomains(policy.MandatoryBlockDomains)
	if err != nil {
		return nil, err
	}
	if len(policy.GlobalSettings) > len(allowedGlobalSettings) {
		return nil, errors.New("too many managed global settings")
	}
	for key, value := range policy.GlobalSettings {
		if _, ok := allowedGlobalSettings[key]; !ok {
			return nil, fmt.Errorf("unsupported managed setting %q", key)
		}
		if err := config.ValidateManagedValue(key, value); err != nil {
			return nil, fmt.Errorf("invalid managed setting %q: %w", key, err)
		}
	}
	if err := profile.ValidateManagedProfileRules(policy.GlobalSettings, policy.ApplicationRules); err != nil {
		return nil, err
	}
	if err := validateNetworkProfiles(policy); err != nil {
		return nil, err
	}
	return domains, nil
}

func applyMandatoryPolicy(policy Policy) error {
	managedPolicyMu.Lock()
	defer managedPolicyMu.Unlock()
	domains, err := validateMandatoryPolicy(policy)
	if err != nil {
		return err
	}
	for key, value := range policy.GlobalSettings {
		if err := config.SetManagedValue(key, value); err != nil {
			return err
		}
	}
	for key := range activeGlobalSettings {
		if _, stillManaged := policy.GlobalSettings[key]; !stillManaged {
			if err := config.SetManagedValue(key, nil); err != nil {
				return err
			}
		}
	}
	if err := profile.SetManagedProfileRules(policy.GlobalSettings, policy.ApplicationRules); err != nil {
		return err
	}
	activeGlobalSettings = policy.GlobalSettings
	mandatoryHistoryDays.Store(int64(policy.LocalHistoryDays))
	mandatoryDomains.Store(&domainBlockPolicy{domains: domains})
	config.SetLocalWritesLocked(true)
	return nil
}

func syncManagedHistorySettings(policy Policy) error {
	enabled := true
	if value, present := policy.GlobalSettings[profile.CfgOptionEnableHistoryKey]; present {
		enabled = value.(bool) // validated before this function is called
	}
	if err := config.SetManagedValue(profile.CfgOptionEnableHistoryKey, enabled); err != nil {
		return err
	}
	return config.SetManagedValue(profile.CfgOptionKeepHistoryKey, policy.LocalHistoryDays)
}

// MandatoryHistoryDays returns the last valid central retention policy. A
// cached policy remains active while the management server is unreachable.
func MandatoryHistoryDays() int64 { return mandatoryHistoryDays.Load() }

type Client struct {
	healthProvider       func() Health
	summaryUploadDelayed atomic.Bool

	policyAvailable             chan struct{}
	policyAvailableOnce         sync.Once
	instanceID                  string
	restartBaseline             map[string]string
	nativeReady                 atomic.Bool
	operationHandlers           OperationHandlers
	operations                  operationRegistry
	operationsEnabled           atomic.Bool
	policyMu                    sync.Mutex
	readNetwork                 func() networkSnapshot
	cachedPolicy                Policy
	networkStatus               atomic.Pointer[networkPolicyStatus]
	connectionLocalIP           atomic.Pointer[string]
	networkWake                 chan struct{}
	mgr                         *mgr.Manager
	dataDir                     string
	httpClient                  *http.Client
	state                       State
	stateMu                     sync.RWMutex
	store                       QueryStore
	binaryUpdater               *updates.Updater
	updateBusy                  atomic.Bool
	applicationCatalogueEnabled atomic.Bool
	compactSummaryEnabled       atomic.Bool
	compactSummaryActive        atomic.Bool
	// Policy transports and local network selection share policyMu.
	lastPolicyJSON []byte
}

type QueryStore interface {
	Execute(context.Context, string, ...orm.QueryOption) error
}

func New(dataDir string, store QueryStore) *Client {
	return &Client{mgr: mgr.New("Enterprise Management"), dataDir: dataDir, instanceID: uuid.NewString(),
		policyAvailable: make(chan struct{}),
		httpClient:      &http.Client{Transport: unconfiguredManagementTransport{}, Timeout: 30 * time.Second, CheckRedirect: noManagementRedirect}, store: store,
		networkWake: make(chan struct{}, 1), readNetwork: currentNetworkSnapshot}
}

func (c *Client) SetBinaryUpdater(updater *updates.Updater) { c.binaryUpdater = updater }

func noManagementRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (c *Client) Manager() *mgr.Manager { return c.mgr }

func (c *Client) Start() error {
	if err := syncInstalledProductMetadata(); err != nil {
		log.Warningf("enterprise: installed application metadata could not be updated: %s", err)
	}
	// A managed installation stays read-only even before its first policy
	// arrives, and remains so if its cached policy or configuration is invalid.
	for _, name := range []string{configFile, stateFile, policyFile} {
		if _, err := os.Stat(filepath.Join(c.dataDir, name)); !errors.Is(err, os.ErrNotExist) {
			config.SetLocalWritesLocked(true)
			break
		}
	}
	if err := secureStoredCredentials(c.dataDir); err != nil {
		log.Warningf("enterprise: management disabled: cannot protect credentials: %s", err)
		return nil
	}
	if data, err := os.ReadFile(filepath.Join(c.dataDir, policyFile)); err == nil {
		var policy Policy
		if json.Unmarshal(data, &policy) == nil {
			if _, err := validateMandatoryPolicy(policy); err == nil {
				snapshot := networkSnapshot{}
				if len(policy.NetworkProfiles) > 0 {
					snapshot = currentNetworkSnapshot()
				}
				c.policyMu.Lock()
				err = c.applyNetworkPolicyLocked(policy, snapshot)
				c.policyMu.Unlock()
				if err != nil {
					log.Warningf("enterprise: cached network policy unavailable: %s", err)
				} else {
					c.compactSummaryEnabled.Store(slices.Contains(policy.Capabilities, "compact-summaries-v2"))
					c.lastPolicyJSON, _ = json.Marshal(policy)
					c.applicationCatalogueEnabled.Store(slices.Contains(policy.Capabilities, "applications-v1"))
				}
			}
		}
	}
	config, err := c.loadConfig()
	if errors.Is(err, os.ErrNotExist) {
		return nil // The management module is opt-in.
	}
	if err != nil {
		log.Warningf("enterprise: management disabled: %s", err)
		return nil
	}
	if err := c.activateCompactCapture(context.Background()); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Warningf("enterprise: compact capture initialization delayed: %s", err)
	}
	c.mgr.Go("local network policy", c.monitorNetworkPolicy)
	c.mgr.Go("outbound management connection", func(w *mgr.WorkerCtx) error {
		c.run(w.Ctx(), config, w)
		return nil
	})
	if c.store != nil {
		c.mgr.Go("compact management telemetry", func(w *mgr.WorkerCtx) error {
			c.telemetryLoop(w.Ctx(), config, w)
			return nil
		})
	}
	return nil
}

func secureStoredCredentials(dataDir string) error {
	for _, name := range []string{configFile, stateFile} {
		file, err := os.Open(filepath.Join(dataDir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		protectErr := setPrivateFilePermissions(file)
		closeErr := file.Close()
		if protectErr != nil {
			return protectErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func (c *Client) Stop() error { return nil }

func (c *Client) loadConfig() (Config, error) {
	var config Config
	data, err := os.ReadFile(filepath.Join(c.dataDir, configFile))
	if err != nil {
		return config, err
	}
	if err = json.Unmarshal(data, &config); err != nil {
		return config, err
	}
	if err = config.Validate(); err != nil {
		return config, err
	}
	c.httpClient = c.privateHTTPClient(config, false)
	if config.Platform == "" {
		config.Platform = runtime.GOOS
	}
	if config.Name == "" {
		config.Name, _ = os.Hostname()
	}
	return config, nil
}

func (c *Client) loadState() error {
	state, err := readIdentity(c.dataDir)
	if err != nil {
		return err
	}
	if state.Credential == "" || state.PrivateKeyPEM == "" {
		return errors.New("incomplete management state")
	}
	c.stateMu.Lock()
	c.state = state
	c.stateMu.Unlock()
	return nil
}
func (c *Client) identitySnapshot() State {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}
func (c *Client) saveIdentity(state State) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	data, err = protectIdentity(data)
	if err != nil {
		return err
	}
	if err = writePrivateBytes(filepath.Join(c.dataDir, stateFile), data); err != nil {
		return err
	}
	c.stateMu.Lock()
	c.state = state
	c.stateMu.Unlock()
	return nil
}
func readIdentity(directory string) (State, error) {
	var state State
	data, err := os.ReadFile(filepath.Join(directory, stateFile))
	if err != nil {
		return state, err
	}
	data, err = unprotectIdentity(data)
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(data, &state)
	return state, err
}
func (c *Client) enroll(ctx context.Context, config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if config.EnrollmentToken == "" {
		return errors.New("enrollment token missing")
	}
	state := c.identitySnapshot()
	if state.PrivateKeyPEM == "" {
		key, err := newDeviceKey()
		if err != nil {
			return err
		}
		secret := make([]byte, 48)
		if _, err = cryptorand.Read(secret); err != nil {
			return err
		}
		state = State{PrivateKeyPEM: key, Credential: base64.RawURLEncoding.EncodeToString(secret), KeyCreatedAt: time.Now().UTC()}
		if err = c.saveIdentity(state); err != nil {
			return err
		}
	}
	csr, err := deviceCSR(state.PrivateKeyPEM)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"token": config.EnrollmentToken, "name": config.Name, "platform": config.Platform, "version": info.VersionNumber(), "credential": state.Credential, "csr": csr, "client_time": time.Now().UTC().Format(time.RFC3339Nano)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.ServerURL+"/api/v1/enroll/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := c.privateHTTPClient(config, true)
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		var failure struct {
			Code string `json:"code"`
		}
		if response.StatusCode == http.StatusBadRequest && json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&failure) == nil && failure.Code == "device_clock" {
			return errors.New("synchronize the device date and time, then retry installation")
		}
		return fmt.Errorf("enrollment rejected with HTTP %d", response.StatusCode)
	}
	if err = c.acceptCertificate(config, &state, response.Body); err != nil {
		return err
	}
	if err = c.saveIdentity(state); err != nil {
		return err
	}
	config.EnrollmentToken = ""
	return writePrivateJSON(filepath.Join(c.dataDir, configFile), config)
}

func writePrivateJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if filepath.Base(path) == stateFile {
		data, err = protectIdentity(data)
		if err != nil {
			return err
		}
	}
	return writePrivateBytes(path, data)
}
func writePrivateBytes(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".management-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = setPrivateFilePermissions(file); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func (c *Client) run(ctx context.Context, config Config, w *mgr.WorkerCtx) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := c.loadState(); errors.Is(err, os.ErrNotExist) {
			if err = c.enroll(ctx, config); err != nil {
				w.Warn("management enrollment failed", "err", err)
			}
		} else if err != nil {
			w.Warn("management credential unavailable", "err", err)
		}
		state := c.identitySnapshot()
		if state.PrivateKeyPEM != "" && state.CertificatePEM == "" {
			if err := c.renewCertificate(ctx, config, false); err != nil && state.DeviceID == "" {
				if err = c.enroll(ctx, config); err != nil {
					w.Warn("management enrollment failed", "err", err)
				}
			}
		}
		if state = c.identitySnapshot(); state.CertificatePEM != "" {
			if config.EnrollmentToken != "" {
				config.EnrollmentToken = ""
				if err := writePrivateJSON(filepath.Join(c.dataDir, configFile), config); err != nil {
					w.Warn("consumed invitation cleanup delayed", "err", err)
				}
			}
			if err := c.maintainCertificate(ctx, config); err != nil {
				w.Warn("device certificate renewal delayed", "err", err)
			}
			if err := c.connect(ctx, config); err != nil && ctx.Err() == nil {
				w.Warn("management connection lost", "err", err)
			}
			if ctx.Err() == nil {
				if err := c.recoverPolicy(ctx, config); err != nil && ctx.Err() == nil {
					w.Warn("private policy recovery delayed", "err", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff + time.Duration(rand.Int64N(int64(backoff/5)))):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (c *Client) connect(ctx context.Context, config Config) error {
	var operationTime operationClock
	connectionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	credential := c.identitySnapshot().Credential
	tlsConn, err := c.openChannel(ctx, config, controlALPN, false)
	if err != nil {
		return err
	}
	conn := &privateControl{Conn: tlsConn, reader: bufio.NewReader(tlsConn)}
	defer conn.Close()
	exchangeStarted := time.Now()
	if err = conn.WriteJSON(map[string]string{"credential": credential}); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(75 * time.Second))
	done := make(chan struct{})
	var writeMu sync.Mutex
	var policyReady atomic.Bool
	writeJSON := func(value any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		return conn.WriteJSON(value)
	}
	var readyMu sync.Mutex
	var lastReady []byte
	writeReady := func() error {
		readyMu.Lock()
		defer readyMu.Unlock()
		message := c.endpointReady()
		if message == nil {
			return nil
		}
		encoded, err := json.Marshal(message)
		if err != nil {
			return err
		}
		if bytes.Equal(encoded, lastReady) {
			return nil
		}
		if err := writeJSON(message); err != nil {
			return err
		}
		lastReady = encoded
		return nil
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				_ = conn.Close()
				return
			case <-c.networkWake:
				if policyReady.Load() {
					if err := writeJSON(c.policyAcknowledgment(true)); err != nil {
						_ = conn.Close()
						return
					}
					if c.operationsEnabled.Load() {
						if err := writeReady(); err != nil {
							_ = conn.Close()
							return
						}
					}
				}
			case <-ticker.C:
				err := writeJSON(c.heartbeatMessage())
				if err != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()
	defer close(done)
	if c.healthProvider != nil {
		if err := writeJSON(c.heartbeatMessage()); err != nil {
			return err
		}
	}
	for {
		var envelope struct {
			Type       string    `json:"type"`
			ServerTime time.Time `json:"server_time"`
		}
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return err
		}

		if policyReady.Load() {
			if _, valid := operationTime.at(time.Now()); !valid {
				return errors.New("management session time reference changed; reconnecting")
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(75 * time.Second))
		if envelope.Type == "policy" {
			if !policyReady.Load() {
				operationTime, err = newOperationClock(envelope.ServerTime, exchangeStarted, time.Now())
				if err != nil {
					return err
				}
			}
			var policy Policy
			if err := json.Unmarshal(data, &policy); err != nil {
				return err
			}
			if err := c.installPolicy(connectionCtx, policy); err != nil {
				return err
			}
			err = writeJSON(c.policyAcknowledgment(true))
			c.operationsEnabled.Store(slices.Contains(policy.Capabilities, "endpoint-operations-v1"))
			if err != nil {
				return err
			}
			policyReady.Store(true)
			if c.operationsEnabled.Load() {
				if err := writeReady(); err != nil {
					return err
				}
			}
		} else if envelope.Type == "query" {
			result := c.queryDetail(ctx, data)
			err := writeJSON(result)
			if err != nil {
				return err
			}
		} else if envelope.Type == "endpoint_operation" {
			if !policyReady.Load() || !c.operationsEnabled.Load() {
				return errors.New("endpoint operations are unavailable")
			}
			if err := c.handleOperation(connectionCtx, operationTime, data, writeJSON); err != nil {
				return err
			}
		} else if envelope.Type == "software_update" {
			var command struct {
				ReleaseID string `json:"release_id"`
				Version   string `json:"version"`
			}
			if err := json.Unmarshal(data, &command); err != nil {
				return err
			}
			if c.binaryUpdater == nil || !c.updateBusy.CompareAndSwap(false, true) {
				continue
			}
			go func() {
				defer c.updateBusy.Store(false)
				status := func(state, reason string) {
					_ = writeJSON(map[string]string{"type": "update_status", "release_id": command.ReleaseID,
						"status": state, "reason": reason})
				}
				status("staging", "")
				if err := c.stageRelease(connectionCtx, config, credential, command.ReleaseID, command.Version); err != nil {
					log.Warningf("enterprise: release staging failed: %s", err)
					status("failed", updateStagingReason(err))
					return
				}
				status("applying", "")
				if err := c.binaryUpdater.ForceUpdate(); err != nil {
					log.Warningf("enterprise: release apply failed: %s", err)
					status("failed", "release installation failed")
				}
			}()
		}
	}
}
