package management

import "github.com/packettale/agents/base/info"

// Health contains bounded operational states, not internal errors or paths.
type Health struct {
	DNS          string `json:"dns"`
	FilterLists  string `json:"filter_lists"`
	Intelligence string `json:"intelligence"`
	Events       string `json:"events,omitempty"`
}

// SetHealthProvider is configured once before the management module starts.
func (c *Client) SetHealthProvider(provider func() Health) { c.healthProvider = provider }

func (c *Client) heartbeatMessage() map[string]any {
	result := map[string]any{"type": "ping", "version": info.VersionNumber()}
	if c.healthProvider != nil {
		health := c.healthProvider()
		health.Events = "disabled"
		if c.compactSummaryEnabled.Load() {
			health.Events = "queued"
			if c.compactSummaryActive.Load() {
				health.Events = "ready"
			}
			if c.summaryUploadDelayed.Load() {
				health.Events = "delayed"
			}
		}
		result["health"] = health
	}
	return result
}
