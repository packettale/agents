package netenv

import (
	"fmt"
	"net"
	"testing"
)

func TestInterfaceAddressesKeepLANIPv6AndInterfaceIdentity(t *testing.T) {
	rows := interfaceAddressRows([]cachedNetInterface{
		{iface: net.Interface{Name: "Ethernet"}, addrs: []net.IP{net.ParseIP("10.23.45.67"), net.ParseIP("10.23.45.67"), net.ParseIP("fd00::1"), net.ParseIP("127.0.0.1"), net.ParseIP("224.0.0.1")}},
		{iface: net.Interface{Name: "VPN"}, addrs: []net.IP{net.ParseIP("10.23.45.67")}},
		{iface: net.Interface{Name: "invalid\nname"}, addrs: []net.IP{net.ParseIP("10.0.0.1")}},
	})
	if len(rows) != 3 || rows[0].Interface != "Ethernet" || rows[0].Address != "10.23.45.67" || rows[1].Address != "fd00::1" || rows[2].Interface != "VPN" {
		t.Fatalf("incorrect interface snapshot: %+v", rows)
	}
	entries := []cachedNetInterface{}
	for i := 0; i < 100; i++ {
		entries = append(entries, cachedNetInterface{iface: net.Interface{Name: fmt.Sprintf("eth%03d", i)}, addrs: []net.IP{net.ParseIP("10.23.45.67")}})
	}
	if got := len(interfaceAddressRows(entries)); got != 64 {
		t.Fatalf("unbounded report: %d", got)
	}
}

func TestAssignedInterfaceAddressesNative(t *testing.T) {
	rows, err := AssignedInterfaceAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Skip("no active addressed interface")
	}
	for _, row := range rows {
		ip := net.ParseIP(row.Address)
		if ip == nil || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
			t.Fatalf("invalid live interface address: %+v", row)
		}
		t.Logf("interface %s: %s", row.Interface, row.Address)
	}
}
