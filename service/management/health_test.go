package management

import (
	"encoding/json"
	"testing"
)

func TestHeartbeatCarriesOperationalHealth(t *testing.T) {
	c := &Client{}
	c.SetHealthProvider(func() Health { return Health{FilterLists: "initializing", Intelligence: "updating"} })
	b, err := json.Marshal(c.heartbeatMessage())
	if err != nil {
		t.Fatal(err)
	}
	var message struct {
		Type   string `json:"type"`
		Health Health `json:"health"`
	}
	if err := json.Unmarshal(b, &message); err != nil {
		t.Fatal(err)
	}
	if message.Type != "ping" || message.Health.FilterLists != "initializing" || message.Health.Intelligence != "updating" {
		t.Fatalf("incomplete health: %s", b)
	}
}
