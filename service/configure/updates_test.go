package configure

import "testing"

func TestSafingIntelligenceIndexIdentity(t *testing.T) {
	// This name is part of Safing's signed update contract, not a UI label.
	if DefaultIntelIndexName != "Portmaster Intel" {
		t.Fatalf("intelligence bootstrap would reject Safing's signed index: %q", DefaultIntelIndexName)
	}
}
