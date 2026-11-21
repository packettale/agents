package netenv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"testing"
)

func TestWindowsMatchingSuffixesIncludeNonDefaultActiveAdapters(t *testing.T) {
	first, _ := windows.UTF16PtrFromString("office.example")
	vpn, _ := windows.UTF16PtrFromString("vpn.example")
	down, _ := windows.UTF16PtrFromString("stale.example")
	third := windows.IpAdapterAddresses{IfIndex: 9, OperStatus: windows.IfOperStatusDown, DnsSuffix: down}
	second := windows.IpAdapterAddresses{IfIndex: 7, OperStatus: windows.IfOperStatusUp, DnsSuffix: vpn, Next: &third}
	primary := windows.IpAdapterAddresses{IfIndex: 2, OperStatus: windows.IfOperStatusUp, DnsSuffix: first, Next: &second}
	got := windowsAdapterDNSSuffixes(&primary)
	if !reflect.DeepEqual(got, []string{"office.example", "vpn.example"}) {
		t.Fatalf("non-default VPN suffix missing: %v", got)
	}
}

func TestWindowsMatchingIncludesPrimarySuffixWithoutAdapterSuffixOrSearchList(t *testing.T) {
	adapter := windows.IpAdapterAddresses{IfIndex: 2, OperStatus: windows.IfOperStatusUp}
	got := windowsNetworkDNSSuffixes(&adapter, "corp.example", nil)
	if !reflect.DeepEqual(got, []string{"corp.example"}) {
		t.Fatalf("primary DNS suffix missing: %v", got)
	}
	// An explicit search list changes resolution order, not the host's assigned domain.
	got = windowsNetworkDNSSuffixes(&adapter, "corp.example", []string{"branch.example"})
	if !reflect.DeepEqual(got, []string{"corp.example", "branch.example"}) {
		t.Fatalf("primary/search suffixes missing: %v", got)
	}
}

func TestWindowsPrimaryDNSSuffixReader(t *testing.T) {
	if _, err := readWindowsPrimaryDNSSuffix(); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkSystemDNSFingerprint(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := systemDNSFingerprint(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func TestWindowsNativeDNSFingerprintChangesWithSuffix(t *testing.T) {
	if os.Getenv("PACKETTALE_TEST_DNS_CHANGE") != "1" {
		t.Skip("requires controlled test interface2 with empty suffix")
	}
	read, err := exec.Command("powershell.exe", "-NoProfile", "-Command", "(Get-DnsClient -InterfaceIndex 2).ConnectionSpecificSuffix").Output()
	if err != nil || len(bytes.TrimSpace(read)) != 0 {
		t.Fatal("test interface must have an empty initial suffix")
	}
	before, err := systemDNSFingerprint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := exec.Command("powershell.exe", "-NoProfile", "-Command", "Set-DnsClient -InterfaceIndex 2 -ConnectionSpecificSuffix ''").Run(); err != nil {
			t.Error(err)
		}
		networkChangedBroadcastFlag.NotifyAndReset()
	}()
	if err := exec.Command("powershell.exe", "-NoProfile", "-Command", "Set-DnsClient -InterfaceIndex 2 -ConnectionSpecificSuffix 'office.management.test'").Run(); err != nil {
		t.Fatal(err)
	}
	after, err := systemDNSFingerprint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("native monitor missed actual DNS-only suffix change")
	}
	networkChangedBroadcastFlag.NotifyAndReset()
	servers := Nameservers()
	if len(servers) == 0 {
		t.Fatal("native default provider found no DNS servers")
	}
	for _, server := range servers {
		found := false
		for _, scope := range server.Search {
			if scope == "office.management.test" {
				found = true
			}
		}
		if !found {
			t.Fatalf("native provider lost assigned suffix: %+v", server)
		}
	}
}

func TestWindowsNativeFingerprintMetricOnlyChange(t *testing.T) {
	indexText := os.Getenv("PACKETTALE_TEST_METRIC_INTERFACE")
	if indexText == "" {
		t.Skip("requires a controlled default interface index; temporarily changes and restores its metric")
	}
	index, err := strconv.ParseUint(indexText, 10, 32)
	if err != nil || index == 0 {
		t.Fatal("invalid controlled interface index")
	}
	previous, err := readWindowsDefaultInterface()
	if err != nil || previous == nil || previous.InterfaceIndex != indexText {
		t.Fatal("controlled interface must be current default")
	}
	command := fmt.Sprintf("$p=Get-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4;[pscustomobject]@{Metric=$p.InterfaceMetric;Automatic=$p.AutomaticMetric.ToString()} | ConvertTo-Json", index)
	output, err := exec.Command("powershell.exe", "-NoProfile", "-Command", command).Output()
	if err != nil {
		t.Fatal(err)
	}
	type metricState struct {
		Metric    uint32
		Automatic string
	}
	var original metricState
	if err := json.Unmarshal(output, &original); err != nil {
		t.Fatal(err)
	}
	if original.Metric > 50000 || (original.Automatic != "Enabled" && original.Automatic != "Disabled") {
		t.Fatal("unexpected controlled interface metric state")
	}
	before, err := systemDNSFingerprint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		restore := fmt.Sprintf("Set-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric %d", index, original.Metric)
		if original.Automatic == "Enabled" {
			restore += fmt.Sprintf(";Set-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4 -AutomaticMetric Enabled", index)
		}
		if output, err := exec.Command("powershell.exe", "-NoProfile", "-Command", restore).CombinedOutput(); err != nil {
			t.Errorf("restore metric: %v %s", err, output)
			return
		}
		output, err := exec.Command("powershell.exe", "-NoProfile", "-Command", command).Output()
		var state metricState
		if err != nil || json.Unmarshal(output, &state) != nil || state != original {
			t.Errorf("interface metric state not restored: got %+v want %+v error %v", state, original, err)
		}
		restored, err := systemDNSFingerprint(context.Background())
		if err != nil || !bytes.Equal(before, restored) {
			t.Errorf("metric restoration did not restore fingerprint: %v", err)
		}
		networkChangedBroadcastFlag.NotifyAndReset()
	})
	set := fmt.Sprintf("Set-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric %d", index, original.Metric+11)
	if output, err := exec.Command("powershell.exe", "-NoProfile", "-Command", set).CombinedOutput(); err != nil {
		t.Fatalf("set metric: %v %s", err, output)
	}
	after, err := systemDNSFingerprint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	current, err := readWindowsDefaultInterface()
	if err != nil || current == nil || !current.IPv4Address.Equal(previous.IPv4Address) || !reflect.DeepEqual(current.DNSServer, previous.DNSServer) {
		t.Fatal("controlled metric change unexpectedly changed addresses/DNS")
	}
	if bytes.Equal(before, after) {
		t.Fatal("native monitor missed actual metric-only default-route change")
	}
}
