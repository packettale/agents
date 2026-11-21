package netenv

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsDefaultRoute struct {
	adapter *windows.IpAdapterAddresses
	row     windows.MibIpForwardRow2
	metric  uint64
}

func windowsRouteIP(address *windows.RawSockaddrInet) net.IP {
	switch address.Family {
	case windows.AF_INET:
		raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(address))
		return net.IPv4(raw.Addr[0], raw.Addr[1], raw.Addr[2], raw.Addr[3])
	case windows.AF_INET6:
		raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(address))
		return append(net.IP(nil), raw.Addr[:]...)
	default:
		return nil
	}
}

func bestWindowsDefaultRoute(adapters *windows.IpAdapterAddresses, rows []windows.MibIpForwardRow2, family uint16, only *windows.IpAdapterAddresses) *windowsDefaultRoute {
	var best *windowsDefaultRoute
	for _, row := range rows {
		if row.DestinationPrefix.Prefix.Family != family || row.DestinationPrefix.PrefixLength != 0 || row.ValidLifetime == 0 || row.Loopback != 0 || row.InterfaceIndex == 0 {
			continue
		}
		for adapter := adapters; adapter != nil; adapter = adapter.Next {
			if only != nil && adapter != only {
				continue
			}
			if adapter.OperStatus != windows.IfOperStatusUp || adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
				continue
			}
			index, interfaceMetric := adapter.IfIndex, adapter.Ipv4Metric
			if family == windows.AF_INET6 {
				index, interfaceMetric = adapter.Ipv6IfIndex, adapter.Ipv6Metric
			}
			if row.InterfaceIndex != index || (row.InterfaceLuid != 0 && row.InterfaceLuid != adapter.Luid) {
				continue
			}
			metric := uint64(row.Metric) + uint64(interfaceMetric)
			better := best == nil || metric < best.metric
			if best != nil && metric == best.metric {
				better = row.InterfaceIndex < best.row.InterfaceIndex
				if row.InterfaceIndex == best.row.InterfaceIndex {
					better = bytes.Compare(windowsRouteIP(&row.NextHop), windowsRouteIP(&best.row.NextHop)) < 0
				}
			}
			if better {
				best = &windowsDefaultRoute{adapter: adapter, row: row, metric: metric}
			}
		}
	}
	return best
}

// Rows are copied before freeing the API-owned table. No native allocation or
// route-table pointer escapes this function.
func readWindowsRoutes() ([]windows.MibIpForwardRow2, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return nil, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	if table == nil {
		return nil, fmt.Errorf("GetIpForwardTable2 returned no table")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	return append([]windows.MibIpForwardRow2(nil), table.Rows()...), nil
}

func windowsDefaultRouteFingerprint(adapters *windows.IpAdapterAddresses, rows []windows.MibIpForwardRow2) []string {
	result := make([]string, 0, 4)
	var primary *windowsDefaultRoute
	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		route := bestWindowsDefaultRoute(adapters, rows, family, nil)
		if route == nil {
			result = append(result, fmt.Sprintf("default:%d:none", family))
			continue
		}
		if primary == nil {
			primary = route
		}
		result = append(result, fmt.Sprintf("default:%d:%d:%d:%d:%s", family, route.row.InterfaceIndex, route.row.InterfaceLuid, route.metric, windowsRouteIP(&route.row.NextHop)))
	}
	// The provider publishes both gateways on its primary adapter. Another
	// adapter may win IPv6 globally, so global winners alone are insufficient.
	if primary != nil {
		for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
			route := bestWindowsDefaultRoute(adapters, rows, family, primary.adapter)
			if route != nil {
				result = append(result, fmt.Sprintf("provider:%d:%d:%d:%d:%s", family, route.row.InterfaceIndex, route.row.InterfaceLuid, route.metric, windowsRouteIP(&route.row.NextHop)))
			}
		}
	}
	return result
}

func defaultInterfaceFromWindows(adapters *windows.IpAdapterAddresses, rows []windows.MibIpForwardRow2, globalSuffixes []string) *DefaultNetInterface {
	chosen := bestWindowsDefaultRoute(adapters, rows, windows.AF_INET, nil)
	if chosen == nil {
		chosen = bestWindowsDefaultRoute(adapters, rows, windows.AF_INET6, nil)
	}
	if chosen == nil {
		return nil
	}
	adapter := chosen.adapter
	result := &DefaultNetInterface{InterfaceIndex: strconv.FormatUint(uint64(chosen.row.InterfaceIndex), 10)}
	v4Preferred, v6Preferred := false, false
	for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
		if address.DadState != windows.IpDadStatePreferred && address.DadState != windows.IpDadStateDeprecated {
			continue
		}
		ip := address.Address.IP()
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		preferred := address.DadState == windows.IpDadStatePreferred
		if ip.To4() != nil {
			if result.IPv4Address == nil || (preferred && !v4Preferred) {
				result.IPv4Address = append(net.IP(nil), ip...)
				v4Preferred = preferred
			}
		} else if result.IPv6Address == nil || (preferred && !v6Preferred) {
			result.IPv6Address = append(net.IP(nil), ip...)
			v6Preferred = preferred
		}
	}
	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		route := bestWindowsDefaultRoute(adapters, rows, family, adapter)
		if route == nil {
			continue
		}
		ip := windowsRouteIP(&route.row.NextHop)
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		if family == windows.AF_INET {
			result.IPv4DefaultGateway = ip
		} else {
			result.IPv6DefaultGateway = ip
		}
	}
	for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
		ip := server.Address.IP()
		// Zone-less link-local DNS is not supported by the current transport.
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || (ip.To4() == nil && ip.IsLinkLocalUnicast()) {
			continue
		}
		result.DNSServer = append(result.DNSServer, append(net.IP(nil), ip...))
	}
	scopes := windowsAdapterScopes(adapter)
	config := &dnsServerConfig{SuffixSearchList: append([]string(nil), globalSuffixes...)}
	if len(scopes) > 0 {
		config.Suffix = scopes[0]
		config.SuffixSearchList = append(config.SuffixSearchList, scopes[1:]...)
	}
	result.DNSServerConfig = config
	return result
}

func readWindowsDefaultInterface() (*DefaultNetInterface, error) {
	data, err := readWindowsDNSConfiguration()
	if err != nil {
		return nil, err
	}
	rows, err := readWindowsRoutes()
	if err != nil {
		return nil, err
	}
	return defaultInterfaceFromWindows(data.adapters, rows, data.globalSuffixes), nil
}
