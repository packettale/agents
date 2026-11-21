package netenv

import (
	"bytes"
	"errors"
	"net"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func defaultRouteFixture(family uint16, index, metric uint32) windows.MibIpForwardRow2 {
	row := windows.MibIpForwardRow2{InterfaceIndex: index, Metric: metric, ValidLifetime: ^uint32(0)}
	row.DestinationPrefix.Prefix.Family = family
	row.NextHop.Family = family
	if family == windows.AF_INET {
		(*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop)).Addr = [4]byte{10, 0, 2, 2}
	} else {
		(*windows.RawSockaddrInet6)(unsafe.Pointer(&row.NextHop)).Addr = [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	}
	return row
}

func TestWindowsNativeDefaultSelection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*windows.IpAdapterAddresses, *windows.IpAdapterAddresses, []windows.MibIpForwardRow2)
		want   string
	}{
		{name: "route plus interface metric", want: "7"},
		{name: "interface metric changes preferred default", mutate: func(a, b *windows.IpAdapterAddresses, _ []windows.MibIpForwardRow2) { b.Ipv4Metric = 100 }, want: "2"},
		{name: "down interface excluded", mutate: func(a, b *windows.IpAdapterAddresses, _ []windows.MibIpForwardRow2) {
			b.OperStatus = windows.IfOperStatusDown
		}, want: "2"},
		{name: "loopback route excluded", mutate: func(a, b *windows.IpAdapterAddresses, r []windows.MibIpForwardRow2) { r[1].Loopback = 1 }, want: "2"},
		{name: "nondefault prefix excluded", mutate: func(a, b *windows.IpAdapterAddresses, r []windows.MibIpForwardRow2) {
			r[1].DestinationPrefix.PrefixLength = 24
		}, want: "2"},
		{name: "expired default excluded", mutate: func(a, b *windows.IpAdapterAddresses, r []windows.MibIpForwardRow2) { r[1].ValidLifetime = 0 }, want: "2"},
		{name: "metric sum cannot wrap", mutate: func(a, b *windows.IpAdapterAddresses, r []windows.MibIpForwardRow2) {
			b.Ipv4Metric = ^uint32(0)
			r[1].Metric = 20
		}, want: "2"},
		{name: "tie deterministic by interface index", mutate: func(a, b *windows.IpAdapterAddresses, r []windows.MibIpForwardRow2) {
			b.Ipv4Metric = 20
			r[1].Metric = 10
		}, want: "2"},
		{name: "IPv4 default preferred", mutate: func(a, b *windows.IpAdapterAddresses, r []windows.MibIpForwardRow2) {
			r[1] = defaultRouteFixture(windows.AF_INET6, 7, 0)
		}, want: "2"},
		{name: "IPv6 only default", mutate: func(a, b *windows.IpAdapterAddresses, r []windows.MibIpForwardRow2) {
			r[0].ValidLifetime = 0
			r[1] = defaultRouteFixture(windows.AF_INET6, 7, 0)
		}, want: "7"},
		{name: "no default", mutate: func(a, b *windows.IpAdapterAddresses, r []windows.MibIpForwardRow2) {
			r[0].ValidLifetime = 0
			r[1].ValidLifetime = 0
		}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			second := windows.IpAdapterAddresses{IfIndex: 7, Ipv6IfIndex: 7, OperStatus: windows.IfOperStatusUp, Ipv4Metric: 5, Ipv6Metric: 5}
			first := windows.IpAdapterAddresses{IfIndex: 2, Ipv6IfIndex: 2, OperStatus: windows.IfOperStatusUp, Ipv4Metric: 20, Ipv6Metric: 20, Next: &second}
			rows := []windows.MibIpForwardRow2{defaultRouteFixture(windows.AF_INET, 2, 10), defaultRouteFixture(windows.AF_INET, 7, 20)}
			if tc.mutate != nil {
				tc.mutate(&first, &second, rows)
			}
			got := defaultInterfaceFromWindows(&first, rows, nil)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("unexpected default: %+v", got)
				}
				return
			}
			if got == nil || got.InterfaceIndex != tc.want {
				t.Fatalf("default=%+v want interface %s", got, tc.want)
			}
		})
	}
}

func TestWindowsNativeRouteFingerprint(t *testing.T) {
	adapter := windows.IpAdapterAddresses{IfIndex: 2, Ipv6IfIndex: 2, OperStatus: windows.IfOperStatusUp, Ipv4Metric: 20, Ipv6Metric: 20}
	rows := []windows.MibIpForwardRow2{defaultRouteFixture(windows.AF_INET, 2, 10), defaultRouteFixture(windows.AF_INET6, 2, 20)}
	before := dnsConfigurationFingerprint(nil, windowsDefaultRouteFingerprint(&adapter, rows))
	reordered := []windows.MibIpForwardRow2{rows[1], rows[0]}
	if !bytes.Equal(before, dnsConfigurationFingerprint(nil, windowsDefaultRouteFingerprint(&adapter, reordered))) {
		t.Fatal("route enumeration order changed fingerprint")
	}
	rows[0].Metric++
	if bytes.Equal(before, dnsConfigurationFingerprint(nil, windowsDefaultRouteFingerprint(&adapter, rows))) {
		t.Fatal("default route metric-only change missed")
	}
}

func TestWindowsEffectiveSearchList(t *testing.T) {
	for _, tc := range []struct {
		name, local, policy string
		present             bool
		want                []string
	}{
		{name: "local", local: "office.example, branch.example", want: []string{"office.example", "branch.example"}},
		{name: "policy overrides local", local: "stale.example", policy: "managed.example", present: true, want: []string{"managed.example"}},
		{name: "explicit empty policy overrides local", local: "stale.example", present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveWindowsDNSSuffixes(tc.local, tc.policy, tc.present); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("suffixes %v want %v", got, tc.want)
			}
		})
	}
}

func TestWindowsDefaultCacheRetainsPendingChange(t *testing.T) {
	defaultInterfaceLock.Lock()
	old, flag := defaultInterface, defaultInterfaceNetworkChangedFlag
	defaultInterface = nil
	defaultInterfaceNetworkChangedFlag = GetNetworkChangedFlag()
	defaultInterfaceLock.Unlock()
	defer func() {
		defaultInterfaceLock.Lock()
		defaultInterface, defaultInterfaceNetworkChangedFlag = old, flag
		defaultInterfaceLock.Unlock()
	}()
	calls := 0
	reader := func() (*DefaultNetInterface, error) { calls++; return &DefaultNetInterface{InterfaceIndex: "2"}, nil }
	if getDefaultInterfaceWithReader(reader) == nil || calls != 1 {
		t.Fatal("initial native read missing")
	}
	if getDefaultInterfaceWithReader(reader) == nil || calls != 1 {
		t.Fatal("cached native snapshot reread")
	}
	networkChangedBroadcastFlag.NotifyAndReset()
	failure := func() (*DefaultNetInterface, error) { return nil, errors.New("controlled native provider error") }
	if got := getDefaultInterfaceWithReader(failure); got != nil {
		t.Fatal("read error returned stale snapshot")
	}
	if getDefaultInterfaceWithReader(reader) == nil || calls != 2 {
		t.Fatal("native read failure consumed invalidation")
	}
	networkChangedBroadcastFlag.NotifyAndReset()
	changedDuringRead := func() (*DefaultNetInterface, error) {
		networkChangedBroadcastFlag.NotifyAndReset()
		return &DefaultNetInterface{InterfaceIndex: "7"}, nil
	}
	if got := getDefaultInterfaceWithReader(changedDuringRead); got == nil || got.InterfaceIndex != "7" {
		t.Fatal("controlled read failed")
	}
	if getDefaultInterfaceWithReader(reader) == nil || calls != 3 {
		t.Fatal("change during native read was swallowed")
	}
}

func TestWindowsNativeDefaultCopiesDNSAddresses(t *testing.T) {
	suffix, _ := windows.UTF16PtrFromString("office.example")
	storage := syscall.RawSockaddrAny{}
	dnsIP := (*windows.RawSockaddrInet4)(unsafe.Pointer(&storage))
	*dnsIP = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: [4]byte{10, 20, 0, 53}}
	server := windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{Sockaddr: &storage, SockaddrLength: int32(unsafe.Sizeof(*dnsIP))}}
	adapter := windows.IpAdapterAddresses{IfIndex: 2, OperStatus: windows.IfOperStatusUp, DnsSuffix: suffix, FirstDnsServerAddress: &server}
	got := defaultInterfaceFromWindows(&adapter, []windows.MibIpForwardRow2{defaultRouteFixture(windows.AF_INET, 2, 1)}, []string{"global.example"})
	if got == nil || len(got.DNSServer) != 1 || !got.DNSServer[0].Equal(net.IPv4(10, 20, 0, 53)) {
		t.Fatalf("lost native DNS: %+v", got)
	}
	dnsIP.Addr[0] = 192
	if !got.DNSServer[0].Equal(net.IPv4(10, 20, 0, 53)) {
		t.Fatal("published DNS snapshot aliases native memory")
	}
	if got.DNSServerConfig == nil || got.DNSServerConfig.Suffix != "office.example" || !reflect.DeepEqual(got.DNSServerConfig.SuffixSearchList, []string{"global.example"}) {
		t.Fatalf("lost assigned DNS scopes: %+v", got.DNSServerConfig)
	}
}

func windowsSocketFixture(ip net.IP) windows.SocketAddress {
	storage := &syscall.RawSockaddrAny{}
	length := int32(unsafe.Sizeof(windows.RawSockaddrInet6{}))
	if v4 := ip.To4(); v4 != nil {
		raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(storage))
		raw.Family = windows.AF_INET
		copy(raw.Addr[:], v4)
		length = int32(unsafe.Sizeof(*raw))
	} else {
		raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(storage))
		raw.Family = windows.AF_INET6
		copy(raw.Addr[:], ip)
	}
	return windows.SocketAddress{Sockaddr: storage, SockaddrLength: length}
}

func TestWindowsNativeAddressesPreferFirstPreferred(t *testing.T) {
	addresses := []windows.IpAdapterUnicastAddress{
		{DadState: windows.IpDadStateInvalid, Address: windowsSocketFixture(net.ParseIP("10.0.2.1"))},
		{DadState: windows.IpDadStateDeprecated, Address: windowsSocketFixture(net.ParseIP("10.0.2.10"))},
		{DadState: windows.IpDadStatePreferred, Address: windowsSocketFixture(net.ParseIP("10.0.2.15"))},
		{DadState: windows.IpDadStatePreferred, Address: windowsSocketFixture(net.ParseIP("10.0.2.16"))},
		{DadState: windows.IpDadStatePreferred, Address: windowsSocketFixture(net.ParseIP("fe80::1"))},
		{DadState: windows.IpDadStatePreferred, Address: windowsSocketFixture(net.ParseIP("2001:db8::1"))},
		{DadState: windows.IpDadStatePreferred, Address: windowsSocketFixture(net.ParseIP("2001:db8::2"))},
	}
	for i := 0; i < len(addresses)-1; i++ {
		addresses[i].Next = &addresses[i+1]
	}
	linkLocal := windows.IpAdapterDnsServerAdapter{Address: windowsSocketFixture(net.ParseIP("fe80::53"))}
	adapter := windows.IpAdapterAddresses{IfIndex: 2, OperStatus: windows.IfOperStatusUp, FirstUnicastAddress: &addresses[0], FirstDnsServerAddress: &linkLocal}
	got := defaultInterfaceFromWindows(&adapter, []windows.MibIpForwardRow2{defaultRouteFixture(windows.AF_INET, 2, 1)}, nil)
	if got == nil || !got.IPv4Address.Equal(net.ParseIP("10.0.2.15")) || !got.IPv6Address.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("preferred addresses lost: %+v", got)
	}
	if len(got.DNSServer) != 0 {
		t.Fatalf("zone-less IPv6 link-local DNS selected: %v", got.DNSServer)
	}
}

func BenchmarkWindowsNativeDefaultDiscovery(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		value, err := readWindowsDefaultInterface()
		if err != nil || value == nil {
			b.Fatalf("native default discovery: value=%v err=%v", value, err)
		}
	}
}

func TestWindowsFingerprintTracksPublishedGatewayOnPrimaryAdapter(t *testing.T) {
	secondary := windows.IpAdapterAddresses{IfIndex: 7, Ipv6IfIndex: 7, OperStatus: windows.IfOperStatusUp}
	primary := windows.IpAdapterAddresses{IfIndex: 2, Ipv6IfIndex: 2, Ipv4Metric: 10, Ipv6Metric: 10, OperStatus: windows.IfOperStatusUp, Next: &secondary}
	rows := []windows.MibIpForwardRow2{
		defaultRouteFixture(windows.AF_INET, 2, 1),
		defaultRouteFixture(windows.AF_INET6, 7, 1),
		defaultRouteFixture(windows.AF_INET6, 2, 10),
		defaultRouteFixture(windows.AF_INET6, 2, 20),
	}
	(*windows.RawSockaddrInet6)(unsafe.Pointer(&rows[2].NextHop)).Addr[15] = 10
	(*windows.RawSockaddrInet6)(unsafe.Pointer(&rows[3].NextHop)).Addr[15] = 11
	original := defaultInterfaceFromWindows(&primary, rows, nil)
	if original == nil || !original.IPv6DefaultGateway.Equal(net.ParseIP("fe80::a")) {
		t.Fatalf("incorrect initial published gateway: %+v", original)
	}
	before := dnsConfigurationFingerprint(nil, windowsDefaultRouteFingerprint(&primary, rows))
	rows[2].Metric = 30
	changed := defaultInterfaceFromWindows(&primary, rows, nil)
	if changed == nil || !changed.IPv6DefaultGateway.Equal(net.ParseIP("fe80::b")) {
		t.Fatalf("metric did not change published gateway: %+v", changed)
	}
	after := dnsConfigurationFingerprint(nil, windowsDefaultRouteFingerprint(&primary, rows))
	if bytes.Equal(before, after) {
		t.Fatal("fingerprint missed changed published gateway behind another adapter's globally best IPv6 route")
	}
	reversed := []windows.MibIpForwardRow2{rows[3], rows[2], rows[1], rows[0]}
	if !bytes.Equal(after, dnsConfigurationFingerprint(nil, windowsDefaultRouteFingerprint(&primary, reversed))) {
		t.Fatal("published gateway fingerprint depends on route enumeration order")
	}
}
