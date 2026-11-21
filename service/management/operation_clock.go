package management

import (
	"errors"
	"time"
)

// operationClock belongs to one authenticated control connection and is never
// persisted. The server stamps its first policy after receiving our credential.
// Adding the whole exchange duration gives a conservative upper bound on server
// time, including time spent in transit. Subsequent elapsed time uses Go's local
// monotonic clock, cross-checked against wall-clock elapsed time to detect
// suspend or clock changes. A changed reference requires a fresh connection.
// Delayed handshakes may reject a valid command early;
// they cannot grant an expired command extra time.
type operationClock struct {
	upper    time.Time
	received time.Time
}

func newOperationClock(serverTime, started, received time.Time) (operationClock, error) {
	elapsed, valid := sessionElapsed(started, received)
	if serverTime.IsZero() || !valid || elapsed > 75*time.Second {
		return operationClock{}, errors.New("invalid management session time reference")
	}
	return operationClock{upper: serverTime.Add(elapsed), received: received}, nil
}

func (c operationClock) at(now time.Time) (time.Time, bool) {
	elapsed, valid := sessionElapsed(c.received, now)
	if c.upper.IsZero() || c.received.IsZero() || !valid {
		return time.Time{}, false
	}
	return c.upper.Add(elapsed), true
}

// Go's monotonic clock can pause during system sleep on some platforms. Using
// the greater elapsed reading prevents sleep or a backwards wall correction
// from extending a command. A significant disagreement invalidates the session;
// the reference must be reacquired from the authenticated server.
func sessionElapsed(started, now time.Time) (time.Duration, bool) {
	return checkedElapsed(now.Sub(started), now.Round(0).Sub(started.Round(0)))
}

func checkedElapsed(monotonic, wall time.Duration) (time.Duration, bool) {
	const maxClockDisagreement = 5 * time.Second
	if monotonic < 0 || wall < 0 || monotonic-wall > maxClockDisagreement || wall-monotonic > maxClockDisagreement {
		return 0, false
	}
	return max(monotonic, wall), true
}
