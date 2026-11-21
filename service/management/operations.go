package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/base/log"
)

// OperationHandlers binds a fixed management vocabulary to existing native functions.
// No command, path, URL or caller-supplied function arguments are accepted.
type OperationHandlers struct {
	Restart             func(context.Context) error
	RefreshIntelligence func(context.Context) error
	ClearDNSCache       func(context.Context) error
	ClearHistory        func(context.Context) error
}

type operationState struct{ action, status, reason string }
type operationRegistry struct {
	sync.Mutex
	completed map[string]operationState
}

type operationCommand struct {
	Type            string    `json:"type"`
	ID              string    `json:"operation_id"`
	Action          string    `json:"action"`
	InstanceID      string    `json:"expected_instance_id"`
	ExpiresAt       time.Time `json:"expires_at"`
	CompletionToken string    `json:"completion_token,omitempty"`
}

func (c *Client) SetOperationHandlers(handlers OperationHandlers) { c.operationHandlers = handlers }

// captureRestartBaseline runs after cached policy is applied and before native
// firewall/resolver modules start. Values are immutable for this core process.
func (c *Client) captureRestartBaseline() {
	c.restartBaseline = make(map[string]string)
	for _, option := range config.ExportOptions() {
		if option.RequiresRestart {
			c.restartBaseline[option.Key] = restartSettingValue(option)
		}
	}
}

func restartSettingValue(option *config.Option) string {
	var value any
	switch option.OptType {
	case config.OptTypeString:
		value = config.GetAsString(option.Key, "")()
	case config.OptTypeStringArray:
		value = config.GetAsStringArray(option.Key, nil)()
	case config.OptTypeInt:
		value = config.GetAsInt(option.Key, 0)()
	case config.OptTypeBool:
		value = config.GetAsBool(option.Key, false)()
	}
	data, _ := json.Marshal(value)
	return string(data)
}

// SetServiceReady is called by the native instance lifecycle, not by the server.
func (c *Client) SetServiceReady(ready bool) {
	c.nativeReady.Store(ready)
	if ready && c.operationsEnabled.Load() {
		select {
		case c.networkWake <- struct{}{}:
		default:
		}
	}
}

func (c *Client) endpointReady() map[string]any {
	if !c.nativeReady.Load() {
		return nil
	}
	pending := false
	for _, option := range config.ExportOptions() {
		baseline, tracked := c.restartBaseline[option.Key]
		changed := tracked && baseline != restartSettingValue(option)
		if changed || (!tracked && option.AnnotationEquals(config.RestartPendingAnnotation, true)) {
			pending = true
			break
		}
	}
	result := c.policyAcknowledgment(false)
	result["type"] = "endpoint_ready"
	result["instance_id"] = c.instanceID
	result["restart_required"] = pending
	// Capability describes this protocol implementation. Installer registration
	// can finish after the service starts; ownership is checked at execution.
	result["remote_uninstall"] = true
	return result
}

func (c *Client) handleOperation(ctx context.Context, clock operationClock, data []byte, write func(any) error) error {
	var command operationCommand
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("invalid operation message")
	}
	id, err := uuid.Parse(command.ID)
	if err != nil || id.String() != command.ID || command.Type != "endpoint_operation" {
		return errors.New("invalid operation identifier")
	}
	var handler func(context.Context) error
	switch command.Action {
	case "restart_service":
		handler = c.operationHandlers.Restart
	case "refresh_intelligence":
		handler = c.operationHandlers.RefreshIntelligence
	case "clear_dns_cache":
		handler = c.operationHandlers.ClearDNSCache
	case "clear_history":
		handler = c.operationHandlers.ClearHistory
	case "uninstall_keep_history", "uninstall_delete_history":
		if !validCompletionToken(command.CompletionToken) {
			return errors.New("invalid uninstall completion credential")
		}
		handler = func(ctx context.Context) error { return c.launchUninstaller(ctx, command) }
	default:
		return errors.New("unknown endpoint operation")
	}
	if command.CompletionToken != "" && command.Action != "uninstall_keep_history" && command.Action != "uninstall_delete_history" {
		return errors.New("unexpected uninstall credential")
	}
	send := func(state operationState) error {
		return write(map[string]string{"type": "operation_status",
			"operation_id": command.ID, "instance_id": c.instanceID, "status": state.status, "reason": state.reason})
	}
	c.operations.Lock()
	if old, ok := c.operations.completed[command.ID]; ok {
		c.operations.Unlock()
		if old.action != command.Action {
			return errors.New("operation identifier already used")
		}
		return send(old)
	}
	if len(c.operations.completed) >= 4096 {
		c.operations.Unlock()
		return errors.New("operation replay registry is full")
	}
	state := operationState{action: command.Action, status: "accepted"}
	serverNow, clockValid := clock.at(time.Now())
	switch {
	case !c.nativeReady.Load():
		state.status = "failed"
		state.reason = "Endpoint services are still starting or stopping."
	case command.InstanceID != c.instanceID:
		state.status = "failed"
		state.reason = "The endpoint process has changed."
	case !clockValid:
		state.status = "failed"
		state.reason = "The management session has no valid time reference."
	case !command.ExpiresAt.After(serverNow):
		state.status = "failed"
		state.reason = "The operation has expired."
	case command.ExpiresAt.After(serverNow.Add(2 * time.Minute)):
		state.status = "failed"
		state.reason = "The operation deadline is invalid."
	case handler == nil:
		state.status = "failed"
		state.reason = "This operation is unavailable."
	case !c.updateBusy.CompareAndSwap(false, true):
		state.status = "failed"
		state.reason = "The endpoint is processing another operation or software update."
	}
	if c.operations.completed == nil {
		c.operations.completed = make(map[string]operationState)
	}
	c.operations.completed[command.ID] = state
	c.operations.Unlock()
	if state.status == "failed" {
		log.Warningf("enterprise: operation %s (%s) rejected: %s", command.ID, command.Action, state.reason)
	}
	if err := send(state); err != nil {
		if state.status == "accepted" {
			c.updateBusy.Store(false)
			c.operations.Lock()
			c.operations.completed[command.ID] = operationState{command.Action, "failed", "Acknowledgment could not be delivered."}
			c.operations.Unlock()
		}
		return err
	}
	if state.status != "accepted" {
		return nil
	}
	go func() {
		actionCtx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		err := actionCtx.Err()
		if err == nil {
			err = handler(actionCtx)
		}
		if err == nil && (command.Action == "restart_service" || command.Action == "uninstall_keep_history" || command.Action == "uninstall_delete_history") {
			c.updateBusy.Store(false)
			return
		} // Restart needs a new process; uninstall needs its detached native receipt.
		result := operationState{action: command.Action, status: "completed"}
		if err != nil {
			result.status = "failed"
			result.reason = "The native operation failed."
		}
		c.operations.Lock()
		c.operations.completed[command.ID] = result
		c.operations.Unlock()
		c.updateBusy.Store(false)
		_ = send(result)
	}()
	return nil
}
