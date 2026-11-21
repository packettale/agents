package main

import (
	"github.com/packettale/agents/service/configure"
	"testing"
)

func TestDownloadRequiresExplicitSigningAuthority(t *testing.T) {
	for _, invalid := range []string{"", "unsigned", "Intel", "unknown"} {
		if store, err := downloadTrustStore(invalid); err == nil || store != nil {
			t.Errorf("unrecognised signing authority %q must be rejected", invalid)
		}
	}
	intel, err := downloadTrustStore("intel")
	if err != nil || intel != configure.IntelSigningTrustStore {
		t.Fatal("incorrect intelligence trust store")
	}
	binary, err := downloadTrustStore("binary")
	if err != nil || binary != configure.BinarySigningTrustStore {
		t.Fatal("incorrect binary trust store")
	}
	if intel == binary {
		t.Fatal("signing authorities must remain separate")
	}
}
