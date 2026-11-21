package netenv

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows change detection uses IP Helper directly. Repeated PowerShell
// processes would be too expensive for the existing network monitor.
type windowsDNSConfiguration struct {
	adapters        *windows.IpAdapterAddresses
	globalSuffixes  []string
	servers         []Nameserver
	extra, suffixes []string
}

func systemDNSFingerprint(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	configuration, extra, readErr := readWindowsSystemDNSConfiguration(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return systemDNSConfigurationFingerprint(configuration, extra, readErr), nil
}

// NetworkDNSSuffixes is independent of default-route DNS selection, so a
// split-tunnel adapter can contribute a matching suffix without a default route.
func NetworkDNSSuffixes() []string {
	data, err := readWindowsDNSConfiguration()
	if err != nil {
		return nil
	}
	return data.suffixes
}

func windowsAdapterScopes(adapter *windows.IpAdapterAddresses) []string {
	var scopes []string
	if suffix := windows.UTF16PtrToString(adapter.DnsSuffix); suffix != "" {
		scopes = append(scopes, suffix)
	}
	for suffix := adapter.FirstDnsSuffix; suffix != nil; suffix = suffix.Next {
		if value := windows.UTF16ToString(suffix.String[:]); value != "" {
			scopes = append(scopes, value)
		}
	}
	return scopes
}

func windowsAdapterDNSSuffixes(adapters *windows.IpAdapterAddresses) []string {
	var scopes []string
	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus == windows.IfOperStatusUp {
			scopes = append(scopes, windowsAdapterScopes(adapter)...)
		}
	}
	return scopes
}

// The computer's primary suffix is independent of both connection-specific
// suffixes and the explicit search list, notably on domain-joined Windows hosts.
func windowsNetworkDNSSuffixes(adapters *windows.IpAdapterAddresses, primary string, search []string) []string {
	suffixes := windowsAdapterDNSSuffixes(adapters)
	if primary != "" {
		suffixes = append(suffixes, primary)
	}
	return append(suffixes, search...)
}

func readWindowsPrimaryDNSSuffix() (string, error) {
	var buffer [256]uint16 // Maximum DNS domain length, including its terminator.
	size := uint32(len(buffer))
	if err := windows.GetComputerNameEx(windows.ComputerNamePhysicalDnsDomain, &buffer[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer[:size]), nil
}

func readWindowsDNSConfiguration() (windowsDNSConfiguration, error) {
	var data windowsDNSConfiguration

	adapters, err := getAdapterAddresses()
	if err != nil {
		return data, err
	}
	data.adapters = adapters
	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp {
			continue
		}
		scopes := windowsAdapterScopes(adapter)
		for _, suffix := range scopes {
			data.extra = append(data.extra, fmt.Sprintf("suffix:%d:%s", adapter.IfIndex, suffix))
		}

		for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
			data.servers = append(data.servers, Nameserver{IP: server.Address.IP(), Search: scopes})
		}
		for gateway := adapter.FirstGatewayAddress; gateway != nil; gateway = gateway.Next {
			data.extra = append(data.extra, fmt.Sprintf("%d:%s", adapter.IfIndex, gateway.Address.IP()))
		}
	}
	global, extra, err := readWindowsGlobalSearchList()
	if err != nil {
		return data, err
	}
	data.globalSuffixes = global
	data.extra = append(data.extra, extra...)
	primary, err := readWindowsPrimaryDNSSuffix()
	if err != nil {
		return data, err
	}
	data.extra = append(data.extra, "primary-suffix:"+primary)
	data.suffixes = windowsNetworkDNSSuffixes(adapters, primary, global)
	return data, nil
}

func effectiveWindowsDNSSuffixes(local, policy string, hasPolicy bool) []string {
	value := local
	if hasPolicy {
		value = policy
	}
	var result []string
	for _, suffix := range strings.Split(value, ",") {
		if suffix = strings.TrimSpace(suffix); suffix != "" {
			result = append(result, suffix)
		}
	}
	return result
}

func readWindowsGlobalSearchList() ([]string, []string, error) {
	paths := []string{
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
	}
	values := make([]string, len(paths))
	present := make([]bool, len(paths))
	extra := make([]string, 0, len(paths))
	for i, path := range paths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, nil, err
		}
		if err == nil {
			value, _, readErr := key.GetStringValue("SearchList")
			key.Close()
			if readErr != nil && !errors.Is(readErr, windows.ERROR_FILE_NOT_FOUND) {
				return nil, nil, readErr
			}
			if readErr == nil {
				values[i], present[i] = value, true
			}
		}
		// Presence matters: explicit empty policy overrides the local search list.
		extra = append(extra, fmt.Sprintf("%s:%t:%s", path, present[i], values[i]))
	}
	return effectiveWindowsDNSSuffixes(values[0], values[1], present[1]), extra, nil
}
