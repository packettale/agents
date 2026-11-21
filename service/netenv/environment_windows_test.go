package netenv

import (
	"os"
	"testing"
)

func TestWindowsDNSDiscoveryIntegration(t *testing.T) {
	expected := os.Getenv("PACKETTALE_TEST_DNS_SUFFIX")
	if expected == "" {
		t.Skip("requires a controlled connection-specific DNS suffix")
	}
	servers := Nameservers()
	if len(servers) == 0 {
		t.Fatal("no system DNS servers discovered")
	}
	for _, server := range servers {
		found := false
		for _, suffix := range server.Search {
			if suffix == expected {
				found = true
			}
		}
		if !found {
			t.Errorf("connection-specific suffix lost: %v, want %s", server, expected)
		}
	}
	t.Logf("system DNS servers: %v", servers)
}

func TestWindowsEnvironment(t *testing.T) {
	defaultIf := GetDefaultInterface()
	if defaultIf == nil {
		t.Error("failed to get default interface")
	}
	t.Logf("default interface: %+v", defaultIf)
}
