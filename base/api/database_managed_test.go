package api

import (
	"strings"
	"testing"

	"github.com/packettale/agents/base/config"
)

func TestManagedEndpointRejectsLocalDatabaseWrites(t *testing.T) { //nolint:paralleltest
	config.SetLocalWritesLocked(true)
	defer config.SetLocalWritesLocked(false)

	for _, request := range []string{
		`7|update|config:filter/blockInbound|J{"Value":false}`,
		`7|create|core:profiles/local/example|J{}`,
		`7|insert|core:profiles/local/example|J{}`,
		`7|delete|core:profiles/local/example`,
		`7|create|core:ui/v1|J{}`,
		`7|update|core:ui/v1|J{}`,
	} {
		var response string
		api := DatabaseAPI{sendBytes: func(data []byte) { response = string(data) }}
		api.Handle([]byte(request))
		if !strings.HasPrefix(response, "7|error|managed endpoint is read-only") {
			t.Errorf("%q: got %q", request, response)
		}
	}
}
