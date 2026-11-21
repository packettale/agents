package config

import (
	"github.com/packettale/agents/base/log"
	"sync/atomic"
)

var localWritesLocked atomic.Bool

// SetLocalWritesLocked prevents local API clients from changing endpoint state.
// The embedded management client can still apply central policy internally.
func SetLocalWritesLocked(locked bool) {
	if _, err := GetOption(CfgManagedEndpointReadOnlyKey); err == nil {
		if err := SetManagedValue(CfgManagedEndpointReadOnlyKey, locked); err != nil {
			log.Errorf("config: failed to publish enterprise read-only status: %s", err)
		}
	}
	localWritesLocked.Store(locked)
}

// LocalWritesLocked reports whether this endpoint is managed as read-only.
func LocalWritesLocked() bool { return localWritesLocked.Load() }

// ValidateManagedValue checks a policy value against a registered option
// without changing its effective or stored value.
func ValidateManagedValue(key string, value any) error {
	option, err := GetOption(key)
	if err != nil {
		return err
	}
	option.Lock()
	defer option.Unlock()
	_, validationErr := validateValue(option, value)
	if validationErr != nil {
		return validationErr
	}
	return nil
}

// SetManagedValue publishes the effective value of a centrally managed option.
// It does not replace the user's stored value. A nil value releases the lock.
func SetManagedValue(key string, value any) error {
	option, err := GetOption(key)
	if err != nil {
		return err
	}

	option.Lock()

	if value == nil {
		option.activeManagedValue = nil
		delete(option.Annotations, ManagedValueAnnotation)
	} else {
		validated, validationErr := validateValue(option, value)
		if validationErr != nil {
			option.Unlock()
			return validationErr
		}
		option.activeManagedValue = validated
		option.setAnnotation(ManagedValueAnnotation, validated.getData(option))
	}
	if dbController != nil {
		pushUpdate(option)
	}
	option.Unlock()
	signalChanges()
	return nil
}
