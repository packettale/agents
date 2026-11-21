package network

import (
	"net"
	"strings"
	"testing"

	"github.com/packettale/agents/service/intel"
)

func TestDebugInfoLineFormatting(t *testing.T) {
	t.Parallel()

	for _, conn := range connectionTestData {
		line := conn.debugInfoLine()
		if line == "" || strings.Contains(line, "%!") {
			t.Fatalf("invalid debug line: %q", line)
		}
	}
}

func TestDebugInfoFormatting(t *testing.T) {
	t.Parallel()

	output := buildNetworkDebugInfoData(connectionTestData)
	if output == "" || strings.Contains(output, "%!") {
		t.Fatalf("invalid debug report: %q", output)
	}
}

// Synthetic records use documentation addresses, fixed dates and dummy process identities.
var connectionTestData = []*Connection{
	{
		ID:         "17-255.255.255.255-29810-192.0.2.23-40672",
		Scope:      "IL",
		IPVersion:  4,
		Inbound:    true,
		IPProtocol: 17,
		LocalIP:    net.ParseIP("255.255.255.255"),
		LocalPort:  29810,
		Entity: &intel.Entity{
			Protocol:      17,
			Port:          40672,
			Domain:        "",
			ReverseDomain: "",
			IP:            net.ParseIP("192.0.2.23"),
			Country:       "",
			ASN:           0,
		},
		Verdict: 2,
		Reason: Reason{
			Msg:       "incoming connection blocked by default",
			OptionKey: "filter/serviceEndpoints",
			Profile:   "",
		},
		Started:          1700000000,
		Ended:            1614010350,
		VerdictPermanent: true,
		Inspecting:       false,
		Tunneled:         false,
		Encrypted:        false,
		ProcessContext: ProcessContext{
			ProcessName: "Unidentified Processes",
			ProfileName: "Unidentified Processes",
			BinaryPath:  "",
			PID:         -1,
			Profile:     "_unidentified",
			Source:      "local",
		},
		Internal:               false,
		ProfileRevisionCounter: 1,
	},
	{
		ID:         "6-192.0.2.10-55216-198.51.100.15-80",
		Scope:      "PI",
		IPVersion:  4,
		Inbound:    false,
		IPProtocol: 6,
		LocalIP:    net.ParseIP("192.0.2.10"),
		LocalPort:  55216,
		Entity: &intel.Entity{
			Protocol:      6,
			Port:          80,
			Domain:        "",
			ReverseDomain: "",
			IP:            net.ParseIP("198.51.100.15"),
			Country:       "DE",
			ASN:           16509,
		},
		Verdict: 2,
		Reason: Reason{
			Msg:       "default permit",
			OptionKey: "filter/defaultAction",
			Profile:   "",
		},
		Started:          1700000060,
		Ended:            1614010565,
		VerdictPermanent: true,
		Inspecting:       false,
		Tunneled:         false,
		Encrypted:        false,
		ProcessContext: ProcessContext{
			ProcessName: "NetworkManager",
			ProfileName: "Example Service",
			BinaryPath:  "/usr/sbin/NetworkManager",
			PID:         1001,
			Profile:     "00000000-0000-4000-8000-000000000001",
			Source:      "local",
		},
		Internal:               true,
		ProfileRevisionCounter: 1,
	},
	{
		ID:         "6-192.0.2.10-49982-203.0.113.20-443",
		Scope:      "pkg.go.dev.",
		IPVersion:  4,
		Inbound:    false,
		IPProtocol: 6,
		LocalIP:    net.ParseIP("192.0.2.10"),
		LocalPort:  49982,
		Entity: &intel.Entity{
			Protocol:      6,
			Port:          443,
			Domain:        "pkg.go.dev.",
			ReverseDomain: "",
			CNAME: []string{
				"ghs.googlehosted.com.",
			},
			IP:      net.ParseIP("203.0.113.20"),
			Country: "US",
			ASN:     15169,
		},
		Verdict: 2,
		Reason: Reason{
			Msg:       "default permit",
			OptionKey: "filter/defaultAction",
			Profile:   "",
		},
		Started:          1700000120,
		Ended:            1614010745,
		VerdictPermanent: true,
		Inspecting:       false,
		Tunneled:         false,
		Encrypted:        false,
		ProcessContext: ProcessContext{
			ProcessName: "firefox",
			ProfileName: "Example Browser",
			BinaryPath:  "/usr/bin/firefox",
			PID:         5710,
			Profile:     "00000000-0000-4000-8000-000000000002",
			Source:      "local",
		},
		Internal:               false,
		ProfileRevisionCounter: 1,
	},
}

func TestDebugReportPreservesCallerOrder(t *testing.T) {
	input := append([]*Connection(nil), connectionTestData...)
	before := append([]*Connection(nil), input...)
	_ = buildNetworkDebugInfoData(input)
	for i := range input {
		if input[i] != before[i] {
			t.Fatal("debug formatting reordered caller data")
		}
	}
}
