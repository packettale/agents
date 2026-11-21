package netenv

import (
	"net"
	"sync"
	"time"

	"github.com/packettale/agents/base/log"
)

// Gateways returns the currently active gateways.
func Gateways() []net.IP {
	defaultIf := GetDefaultInterface()
	if defaultIf == nil {
		return nil
	}

	// Collect gateways.
	var gw []net.IP
	if defaultIf.IPv4DefaultGateway != nil {
		gw = append(gw, defaultIf.IPv4DefaultGateway)
	}
	if defaultIf.IPv6DefaultGateway != nil {
		gw = append(gw, defaultIf.IPv6DefaultGateway)
	}

	return gw
}

// Nameservers returns the currently active nameservers.
func Nameservers() []Nameserver {
	return nameserversFromWindowsDefault(GetDefaultInterface())
}

func nameserversFromWindowsDefault(defaultIf *DefaultNetInterface) []Nameserver {
	if defaultIf == nil {
		return nil
	}

	// Compile search list.
	var search []string
	if defaultIf.DNSServerConfig != nil {
		if defaultIf.DNSServerConfig.Suffix != "" {
			search = append(search, defaultIf.DNSServerConfig.Suffix)
		}
		if len(defaultIf.DNSServerConfig.SuffixSearchList) > 0 {
			search = append(search, defaultIf.DNSServerConfig.SuffixSearchList...)
		}
	}

	// Compile nameservers.
	var ns []Nameserver
	for _, nsIP := range defaultIf.DNSServer {
		ns = append(ns, Nameserver{
			IP:     nsIP,
			Search: search,
		})
	}

	return ns
}

var (
	defaultInterface                   *DefaultNetInterface
	defaultInterfaceLock               sync.Mutex
	defaultInterfaceNetworkChangedFlag = GetNetworkChangedFlag()
)

type DefaultNetInterface struct {
	InterfaceIndex     string
	IPv6Address        net.IP
	IPv4Address        net.IP
	IPv6DefaultGateway net.IP
	IPv4DefaultGateway net.IP
	DNSServer          []net.IP
	DNSServerConfig    *dnsServerConfig
}

type dnsServerConfig struct {
	Suffix           string `json:"ConnectionSpecificSuffix"`
	SuffixSearchList []string
}

func GetDefaultInterface() *DefaultNetInterface {
	return getDefaultInterfaceWithReader(readWindowsDefaultInterface)
}

// Keep invalidations that arrive while the OS snapshot is being read. Refresh
// a separate candidate flag before reading, then publish it only on success.
func getDefaultInterfaceWithReader(read func() (*DefaultNetInterface, error)) *DefaultNetInterface {
	defaultInterfaceLock.Lock()
	defer defaultInterfaceLock.Unlock()
	if !defaultInterfaceNetworkChangedFlag.IsSet() {
		return defaultInterface
	}
	nextFlag := GetNetworkChangedFlag()
	nextFlag.Refresh()
	current, err := read()
	if err != nil {
		defaultInterface = nil
		log.Warningf("netenv: failed to read native Windows network configuration: %s", err)
		RetryDNSDiscoveryAfter(30 * time.Second)
		return nil
	}
	defaultInterface = current
	defaultInterfaceNetworkChangedFlag = nextFlag
	return defaultInterface
}
