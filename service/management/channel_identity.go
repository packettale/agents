package management

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

func validateDeviceCertificate(config Config, state State) error {
	manifest, err := config.channelManifest()
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair([]byte(state.CertificatePEM), []byte(state.PrivateKeyPEM))
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(manifest.CAPEM))
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return err
	}
	if cert.Subject.CommonName != state.DeviceID {
		return errors.New("device certificate identity mismatch")
	}
	return nil
}

func (c *Client) acceptCertificate(config Config, state *State, body io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(body, 8193))
	if err != nil {
		return err
	}
	var response struct {
		DeviceID       string `json:"device_id"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if len(data) > 8192 || json.Unmarshal(data, &response) != nil || response.DeviceID == "" || response.CertificatePEM == "" {
		return errors.New("invalid device certificate response")
	}
	if state.DeviceID != "" && state.DeviceID != response.DeviceID {
		return errors.New("renewal changed device identity")
	}
	state.DeviceID = response.DeviceID
	state.CertificatePEM = response.CertificatePEM
	return validateDeviceCertificate(config, *state)
}

func certificateNeedsRenewal(state State) bool {
	block, _ := pem.Decode([]byte(state.CertificatePEM))
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	return err != nil || time.Until(cert.NotAfter) < 30*24*time.Hour
}

func (c *Client) maintainCertificate(ctx context.Context, config Config) error {
	state := c.identitySnapshot()
	rotate := time.Since(state.KeyCreatedAt) > 30*24*time.Hour
	if rotate || state.PendingKeyPEM != "" || certificateNeedsRenewal(state) {
		return c.renewCertificate(ctx, config, rotate)
	}
	return nil
}

func (c *Client) renewCertificate(ctx context.Context, config Config, rotate bool) error {
	state := c.identitySnapshot()
	if state.PrivateKeyPEM == "" {
		return errors.New("no device key available")
	}
	// Renew an expired identity before asking for a new key. Only a current,
	// mutually authenticated connection may authorise a key change.
	if certificateNeedsRenewal(state) && state.PendingKeyPEM == "" {
		rotate = false
	}
	if rotate && state.PendingKeyPEM == "" {
		key, err := newDeviceKey()
		if err != nil {
			return err
		}
		state.PendingKeyPEM = key
		if err = c.saveIdentity(state); err != nil {
			return err
		}
	}
	key := state.PrivateKeyPEM
	if state.PendingKeyPEM != "" {
		key = state.PendingKeyPEM
	}
	csr, err := deviceCSR(key)
	if err != nil {
		return err
	}
	oldCSR, err := deviceCSR(state.PrivateKeyPEM)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"credential": state.Credential, "csr": csr, "current_csr": oldCSR})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.ServerURL+"/api/v1/device/certificate/renew/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	client := c.privateHTTPClient(config, certificateNeedsRenewal(state))
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("device certificate renewal HTTP %d", response.StatusCode)
	}
	if state.PendingKeyPEM != "" {
		state.PrivateKeyPEM = state.PendingKeyPEM
		state.PendingKeyPEM = ""
		state.KeyCreatedAt = time.Now().UTC()
	}
	if err = c.acceptCertificate(config, &state, response.Body); err != nil {
		return err
	}
	if err = c.saveIdentity(state); err != nil {
		return err
	}
	c.httpClient.CloseIdleConnections()
	return nil
}
