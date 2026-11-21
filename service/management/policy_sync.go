package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"

	"github.com/packettale/agents/base/info"
	"github.com/packettale/agents/base/log"
)

// installPolicy is shared by WSS and HTTPS, which run serially. Identical
// deliveries retry their acknowledgment without rewriting the offline cache.
func (c *Client) installPolicy(ctx context.Context, policy Policy) error {
	c.policyMu.Lock()
	defer c.policyMu.Unlock()
	snapshot := networkSnapshot{}
	if len(policy.NetworkProfiles) > 0 {
		snapshot = c.readNetwork()
	}
	if policy.Type != "policy" {
		return errors.New("unexpected management policy type")
	}
	if _, err := validateMandatoryPolicy(policy); err != nil {
		return err
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	if bytes.Equal(c.lastPolicyJSON, data) {
		return nil
	}
	if err := writePrivateJSON(filepath.Join(c.dataDir, policyFile), policy); err != nil {
		return err
	}
	if err := c.applyNetworkPolicyLocked(policy, snapshot); err != nil {
		return err
	}
	c.applicationCatalogueEnabled.Store(slices.Contains(policy.Capabilities, "applications-v1"))
	c.compactSummaryEnabled.Store(slices.Contains(policy.Capabilities, "compact-summaries-v2"))
	if err := c.activateCompactCapture(ctx); err != nil {
		log.Warningf("enterprise: compact capture initialization delayed: %s", err)
	}
	c.lastPolicyJSON = data
	return nil
}

// recoverPolicy uses a separate inner HTTP stream after the control stream
// fails. Both policy delivery and acknowledgment remain inside private TLS.
func (c *Client) recoverPolicy(ctx context.Context, config Config) error {
	endpoint := config.ServerURL + "/api/v1/device/policy/"
	httpClient := *c.httpClient
	httpClient.CheckRedirect = noManagementRedirect
	request := func(method string, body io.Reader) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.identitySnapshot().Credential)
		req.Header.Set("Cache-Control", "no-store")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return httpClient.Do(req)
	}
	response, err := request(http.MethodGet, nil)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("policy download rejected with HTTP %d", response.StatusCode)
	}
	if readErr != nil {
		return readErr
	}
	if len(data) > 65536 {
		return errors.New("management policy exceeds size limit")
	}
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return err
	}
	if err := c.installPolicy(ctx, policy); err != nil {
		return err
	}
	report := c.policyAcknowledgment(false)
	report["version"] = info.VersionNumber()
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	response, err = request(http.MethodPost, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("policy acknowledgment rejected with HTTP %d", response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return err
	}
	var ack struct {
		Accepted bool `json:"accepted"`
		Revision int  `json:"revision"`
	}
	if len(data) > 4096 || json.Unmarshal(data, &ack) != nil || !ack.Accepted || ack.Revision != policy.Revision {
		return errors.New("invalid policy acknowledgment")
	}
	return nil
}
