package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/netenv"
)

type NetworkProfile struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Enabled        bool           `json:"enabled"`
	CIDRs          []string       `json:"cidrs"`
	DNSSuffixes    []string       `json:"dns_suffixes"`
	GlobalSettings map[string]any `json:"global_settings"`
}

type networkSnapshot struct {
	addresses []netip.Addr
	suffixes  []string
}

type networkPolicyStatus struct {
	Revision   int
	ProfileID  string
	Configured bool
}

func validateNetworkProfiles(policy Policy) error {
	data, err := json.Marshal(policy)
	if err != nil || len(data) > 65536 || len(policy.NetworkProfiles) > 10 {
		return errors.New("network policy exceeds size limit")
	}
	ids := make(map[string]bool)
	for _, entry := range policy.NetworkProfiles {
		id, err := uuid.Parse(entry.ID)
		if err != nil || id.String() != entry.ID || ids[entry.ID] {
			return errors.New("invalid or duplicate network profile ID")
		}
		ids[entry.ID] = true
		if !utf8.ValidString(entry.Name) || utf8.RuneCountInString(entry.Name) < 1 || utf8.RuneCountInString(entry.Name) > 80 || strings.IndexFunc(entry.Name, unicode.IsControl) >= 0 || strings.TrimSpace(entry.Name) != entry.Name {
			return errors.New("invalid network profile name")
		}
		if len(entry.CIDRs) > 20 || len(entry.DNSSuffixes) > 20 || len(entry.CIDRs)+len(entry.DNSSuffixes) == 0 {
			return errors.New("network profile requires bounded matching criteria")
		}
		for _, cidr := range entry.CIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return fmt.Errorf("invalid network CIDR: %w", err)
			}
		}
		for _, suffix := range entry.DNSSuffixes {
			value := strings.ToLower(strings.TrimSuffix(suffix, "."))
			if len(value) == 0 || len(value) > 253 {
				return errors.New("invalid network DNS suffix")
			}
			for _, label := range strings.Split(value, ".") {
				if !domainLabel.MatchString(label) {
					return errors.New("invalid network DNS suffix")
				}
			}
		}
		merged := policy
		merged.NetworkProfiles = nil
		merged.GlobalSettings = maps.Clone(policy.GlobalSettings)
		if merged.GlobalSettings == nil {
			merged.GlobalSettings = make(map[string]any)
		}
		maps.Copy(merged.GlobalSettings, entry.GlobalSettings)
		if _, err := validateMandatoryPolicy(merged); err != nil {
			return fmt.Errorf("invalid network profile settings: %w", err)
		}
	}
	return nil
}

func selectNetworkPolicy(policy Policy, snapshot networkSnapshot) (Policy, string) {
	effective := policy
	effective.NetworkProfiles = nil
	effective.GlobalSettings = maps.Clone(policy.GlobalSettings)
	for _, entry := range policy.NetworkProfiles {
		if !entry.Enabled {
			continue
		}
		addressMatch := len(entry.CIDRs) == 0
		for _, cidr := range entry.CIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			for _, address := range snapshot.addresses {
				if prefix.Contains(address.Unmap()) {
					addressMatch = true
				}
			}
		}
		suffixMatch := len(entry.DNSSuffixes) == 0
		for _, suffix := range entry.DNSSuffixes {
			want := strings.ToLower(strings.TrimSuffix(suffix, "."))
			for _, observed := range snapshot.suffixes {
				value := strings.ToLower(strings.TrimSuffix(observed, "."))
				if value == want || strings.HasSuffix(value, "."+want) {
					suffixMatch = true
				}
			}
		}
		if addressMatch && suffixMatch {
			if effective.GlobalSettings == nil {
				effective.GlobalSettings = make(map[string]any)
			}
			maps.Copy(effective.GlobalSettings, entry.GlobalSettings)
			return effective, entry.ID
		}
	}
	return effective, ""
}

func currentNetworkSnapshot() networkSnapshot {
	var snapshot networkSnapshot
	interfaces, err := net.Interfaces()
	if err != nil {
		return snapshot
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && !prefix.Addr().IsUnspecified() && !prefix.Addr().IsLoopback() {
				snapshot.addresses = append(snapshot.addresses, prefix.Addr().Unmap())
			}
		}
	}
	snapshot.suffixes = netenv.NetworkDNSSuffixes()
	return snapshot
}

// Caller holds policyMu. Only the immutable base policy is persisted; current
// network selection is recomputed locally, including while management is offline.
func (c *Client) applyNetworkPolicyLocked(policy Policy, snapshot networkSnapshot) error {
	effective, id := selectNetworkPolicy(policy, snapshot)
	if err := applyMandatoryPolicy(effective); err != nil {
		return err
	}
	if err := syncManagedHistorySettings(effective); err != nil {
		return err
	}
	c.cachedPolicy = policy
	c.networkStatus.Store(&networkPolicyStatus{Revision: policy.Revision, ProfileID: id, Configured: len(policy.NetworkProfiles) > 0})
	c.policyAvailableOnce.Do(func() { close(c.policyAvailable) })
	return nil
}

func (c *Client) policyAcknowledgment(withType bool) map[string]any {
	result := map[string]any{}
	if withType {
		result["type"] = "policy_applied"
	}
	if status := c.networkStatus.Load(); status != nil {
		result["revision"] = status.Revision
		if status.Configured {
			result["network_profile_id"] = status.ProfileID
		}
	}
	return result
}

func (c *Client) monitorNetworkPolicy(w *mgr.WorkerCtx) error {
	flag := netenv.GetNetworkChangedFlag()
	for {
		select {
		case <-w.Done():
			return nil
		case <-flag.Signal():
			flag.Refresh()
		}
		c.policyMu.Lock()
		configured := len(c.cachedPolicy.NetworkProfiles) > 0
		c.policyMu.Unlock()
		if !configured {
			continue
		}
		c.policyMu.Lock()
		snapshot := c.readNetwork()
		previous := c.networkStatus.Load()
		if c.cachedPolicy.Revision < 1 || len(c.cachedPolicy.NetworkProfiles) == 0 {
			c.policyMu.Unlock()
			continue
		}
		_, id := selectNetworkPolicy(c.cachedPolicy, snapshot)
		if previous != nil && previous.ProfileID == id {
			c.policyMu.Unlock()
			continue
		}
		err := c.applyNetworkPolicyLocked(c.cachedPolicy, snapshot)
		c.policyMu.Unlock()
		if err != nil {
			log.Warningf("enterprise: network policy application delayed: %s", err)
			continue
		}
		select {
		case c.networkWake <- struct{}{}:
		default:
		}
		// Coalesce rapid interface events without adding work to packet handling.
		select {
		case <-w.Done():
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
}
