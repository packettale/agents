package management

import "context"

// StartEnforcement waits for an administrator policy before native networking
// modules start. A fresh enrollment must use the machine's working network,
// rather than intercepting DNS or blocking inbound traffic with factory defaults.
func (c *Client) StartEnforcement(ctx context.Context, start func() error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.policyAvailable:
	}

	c.policyMu.Lock()
	defer c.policyMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// The network may have changed while enrollment or other modules started.
	// Select its policy before any packet interception or DNS listeners start.
	snapshot := networkSnapshot{}
	if len(c.cachedPolicy.NetworkProfiles) > 0 {
		snapshot = c.readNetwork()
	}
	if err := c.applyNetworkPolicyLocked(c.cachedPolicy, snapshot); err != nil {
		return err
	}
	c.captureRestartBaseline()
	if err := start(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.SetServiceReady(true)
	return nil
}
