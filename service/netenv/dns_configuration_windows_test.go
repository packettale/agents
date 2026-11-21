package netenv

import (
	"net"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsLinkDNSRoutingIncludesNonDefaultActiveAdapter(t *testing.T) {
	suffix, _ := windows.UTF16PtrFromString("corp.policy-fixture.com")
	stale, _ := windows.UTF16PtrFromString("stale.policy-fixture.com")
	address := windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: [4]byte{10, 20, 0, 53}}
	server := windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(&address)), SockaddrLength: int32(unsafe.Sizeof(address))}}
	down := windows.IpAdapterAddresses{IfIndex: 9, OperStatus: windows.IfOperStatusDown, DnsSuffix: stale, FirstDnsServerAddress: &server}
	vpn := windows.IpAdapterAddresses{IfIndex: 7, OperStatus: windows.IfOperStatusUp, DnsSuffix: suffix, FirstDnsServerAddress: &server, Next: &down}
	primary := windows.IpAdapterAddresses{IfIndex: 2, OperStatus: windows.IfOperStatusUp, Next: &vpn}
	rules, err := windowsLinkDNSRules(&primary)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Namespace != "corp.policy-fixture.com." || len(rules[0].Servers) != 1 || !rules[0].Servers[0].Equal(net.ParseIP("10.20.0.53")) {
		t.Fatalf("non-default DNS scope lost or inactive adapter included: %+v", rules)
	}
}

func TestWindowsLinkDNSRoutingRetainsMissingUpstream(t *testing.T) {
	suffix, _ := windows.UTF16PtrFromString("corp.policy-fixture.com")
	adapter := windows.IpAdapterAddresses{IfIndex: 7, OperStatus: windows.IfOperStatusUp, DnsSuffix: suffix}
	rules, err := windowsLinkDNSRules(&adapter)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || len(rules[0].Servers) != 0 {
		t.Fatalf("missing server relaxed private namespace: %+v", rules)
	}
}
