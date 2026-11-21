//go:build !server

package netenv

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

var (
	dbusConn     *dbus.Conn
	dbusConnLock sync.Mutex
)

func getNameserversFromDbus() ([]Nameserver, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return getNameserversFromDbusContext(ctx)
}

func getNameserversFromDbusContext(ctx context.Context) ([]Nameserver, error) {
	configuration, err := getLinkDNSConfigurationFromDbusContext(ctx)
	return configuration.Nameservers, err
}

func getDNSConfigurationFromDbusContext(ctx context.Context) (SystemDNSConfiguration, error) {
	conn, err := networkManagerBus()
	if err != nil {
		return SystemDNSConfiguration{}, dnsProviderInitialError(err)
	}
	var properties map[string]dbus.Variant
	err = conn.Object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager").
		CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart,
			"org.freedesktop.NetworkManager.DnsManager").Store(&properties)
	if err != nil {
		return SystemDNSConfiguration{}, fmt.Errorf("read NetworkManager DNS policy: %w", dnsProviderInitialError(err))
	}
	return networkManagerDNSProperties(properties)
}

// Preserve the legacy link reader for callers of Nameservers. The resolver's
// policy snapshot uses DnsManager's current domains and effective priorities.
func getLinkDNSConfigurationFromDbusContext(ctx context.Context) (SystemDNSConfiguration, error) {
	var configuration SystemDNSConfiguration
	var discoveryErr error
	conn, err := networkManagerBus()
	if err != nil {
		return configuration, dnsProviderInitialError(err)
	}

	primaryConnectionVariant, err := getNetworkManagerPropertyContext(ctx, conn, dbus.ObjectPath("/org/freedesktop/NetworkManager"), "org.freedesktop.NetworkManager.PrimaryConnection")
	if err != nil {
		return configuration, fmt.Errorf("dbus: failed to access NetworkManager.PrimaryConnection: %w", dnsProviderInitialError(err))
	}
	primaryConnection, ok := primaryConnectionVariant.Value().(dbus.ObjectPath)
	if !ok {
		return configuration, errors.New("dbus: could not assert type of /org/freedesktop/NetworkManager:org.freedesktop.NetworkManager.PrimaryConnection")
	}

	activeConnectionsVariant, err := getNetworkManagerPropertyContext(ctx, conn, dbus.ObjectPath("/org/freedesktop/NetworkManager"), "org.freedesktop.NetworkManager.ActiveConnections")
	if err != nil {
		return configuration, fmt.Errorf("dbus: failed to access NetworkManager.ActiveConnections: %w", err)
	}
	activeConnections, ok := activeConnectionsVariant.Value().([]dbus.ObjectPath)
	if !ok {
		return configuration, errors.New("dbus: could not assert type of /org/freedesktop/NetworkManager:org.freedesktop.NetworkManager.ActiveConnections")
	}

	sortedConnections := []dbus.ObjectPath{primaryConnection}
	for _, activeConnection := range activeConnections {
		if !objectPathInSlice(activeConnection, sortedConnections) {
			sortedConnections = append(sortedConnections, activeConnection)
		}
	}

	for _, activeConnection := range sortedConnections {
		if err := ctx.Err(); err != nil {
			return configuration, err
		}
		next, err := dbusGetInterfaceDNSConfiguration(ctx, conn, activeConnection, 4)
		if err != nil {
			discoveryErr = errors.Join(discoveryErr, err)
		} else {
			configuration.Nameservers = append(configuration.Nameservers, next.Nameservers...)
			configuration.Rules = append(configuration.Rules, next.Rules...)
		}

		next, err = dbusGetInterfaceDNSConfiguration(ctx, conn, activeConnection, 6)
		if err != nil {
			discoveryErr = errors.Join(discoveryErr, err)
		} else {
			configuration.Nameservers = append(configuration.Nameservers, next.Nameservers...)
			configuration.Rules = append(configuration.Rules, next.Rules...)
		}
	}

	rules, err := NormalizeDNSRoutingRules(configuration.Rules)
	if err != nil {
		return configuration, err
	}
	configuration.Rules = rules
	return configuration, discoveryErr
}

func dbusGetInterfaceNameservers(ctx context.Context, conn *dbus.Conn, object dbus.ObjectPath, version uint8) ([]Nameserver, error) {
	configuration, err := dbusGetInterfaceDNSConfiguration(ctx, conn, object, version)
	return configuration.Nameservers, err
}

func dbusGetInterfaceDNSConfiguration(ctx context.Context, dbusConn *dbus.Conn, interfaceObject dbus.ObjectPath, ipVersion uint8) (SystemDNSConfiguration, error) {
	ipConfigPropertyKey := fmt.Sprintf("org.freedesktop.NetworkManager.Connection.Active.Ip%dConfig", ipVersion)
	nameserversIPsPropertyKey := fmt.Sprintf("org.freedesktop.NetworkManager.IP%dConfig.Nameservers", ipVersion)
	nameserversDomainsPropertyKey := fmt.Sprintf("org.freedesktop.NetworkManager.IP%dConfig.Domains", ipVersion)
	nameserversSearchesPropertyKey := fmt.Sprintf("org.freedesktop.NetworkManager.IP%dConfig.Searches", ipVersion)

	// Get Interface Configuration.
	ipConfigVariant, err := getNetworkManagerPropertyContext(ctx, dbusConn, interfaceObject, ipConfigPropertyKey)
	if err != nil {
		return SystemDNSConfiguration{}, fmt.Errorf("failed to access %s:%s: %w", interfaceObject, ipConfigPropertyKey, err)
	}
	ipConfig, ok := ipConfigVariant.Value().(dbus.ObjectPath)
	if !ok {
		return SystemDNSConfiguration{}, fmt.Errorf("could not assert type of %s:%s", interfaceObject, ipConfigPropertyKey)
	}

	// Check if interface is active in the selected IP version
	if !ipConfig.IsValid() || ipConfig == "/" {
		return SystemDNSConfiguration{}, nil
	}

	// Get Nameserver IPs
	nameserverIPsVariant, err := getNetworkManagerPropertyContext(ctx, dbusConn, ipConfig, nameserversIPsPropertyKey)
	if err != nil {
		return SystemDNSConfiguration{}, fmt.Errorf("failed to access %s:%s: %w", ipConfig, nameserversIPsPropertyKey, err)
	}
	var nameserverIPs []net.IP
	switch ipVersion {
	case 4:
		nameserverIP4s, ok := nameserverIPsVariant.Value().([]uint32)
		if !ok {
			return SystemDNSConfiguration{}, fmt.Errorf("could not assert type of %s:%s", ipConfig, nameserversIPsPropertyKey)
		}
		for _, ip := range nameserverIP4s {
			a := uint8(ip / 16777216)
			b := uint8((ip % 16777216) / 65536)
			c := uint8((ip % 65536) / 256)
			d := uint8(ip % 256)
			nameserverIPs = append(nameserverIPs, net.IPv4(d, c, b, a))
		}
	case 6:
		nameserverIP6s, ok := nameserverIPsVariant.Value().([][]byte)
		if !ok {
			return SystemDNSConfiguration{}, fmt.Errorf("could not assert type of %s:%s", ipConfig, nameserversIPsPropertyKey)
		}
		for _, ip := range nameserverIP6s {
			if len(ip) != 16 {
				return SystemDNSConfiguration{}, fmt.Errorf("query returned IPv6 address with invalid length: %q", ip)
			}
			nameserverIPs = append(nameserverIPs, net.IP(ip))
		}
	}

	// Get Nameserver Domains
	nameserverDomainsVariant, err := getNetworkManagerPropertyContext(ctx, dbusConn, ipConfig, nameserversDomainsPropertyKey)
	if err != nil {
		return SystemDNSConfiguration{}, fmt.Errorf("failed to access %s:%s: %w", ipConfig, nameserversDomainsPropertyKey, err)
	}
	nameserverDomains, ok := nameserverDomainsVariant.Value().([]string)
	if !ok {
		return SystemDNSConfiguration{}, fmt.Errorf("could not assert type of %s:%s", ipConfig, nameserversDomainsPropertyKey)
	}

	// Get Nameserver Searches
	nameserverSearchesVariant, err := getNetworkManagerPropertyContext(ctx, dbusConn, ipConfig, nameserversSearchesPropertyKey)
	if err != nil {
		return SystemDNSConfiguration{}, fmt.Errorf("failed to access %s:%s: %w", ipConfig, nameserversSearchesPropertyKey, err)
	}
	nameserverSearches, ok := nameserverSearchesVariant.Value().([]string)
	if !ok {
		return SystemDNSConfiguration{}, fmt.Errorf("could not assert type of %s:%s", ipConfig, nameserversSearchesPropertyKey)
	}

	return networkManagerDNSConfiguration(nameserverIPs, nameserverDomains, nameserverSearches)
}

func getConnectivityStateFromDbus() (OnlineStatus, error) {
	conn, err := networkManagerBus()
	if err != nil {
		return 0, err
	}

	connectivityStateVariant, err := getNetworkManagerProperty(conn, dbus.ObjectPath("/org/freedesktop/NetworkManager"), "org.freedesktop.NetworkManager.Connectivity")
	if err != nil {
		return 0, err
	}
	connectivityState, ok := connectivityStateVariant.Value().(uint32)
	if !ok {
		return 0, errors.New("dbus: could not assert type of /org/freedesktop/NetworkManager:org.freedesktop.NetworkManager.Connectivity")
	}

	// NMConnectivityState
	// NM_CONNECTIVITY_UNKNOWN	= 0 Network connectivity is unknown.
	// NM_CONNECTIVITY_NONE = 1 The host is not connected to any network.
	// NM_CONNECTIVITY_PORTAL = 2 The host is behind a captive portal and cannot reach the full Internet.
	// NM_CONNECTIVITY_LIMITED = 3 The host is connected to a network, but does not appear to be able to reach the full Internet.
	// NM_CONNECTIVITY_FULL = 4 The host is connected to a network, and appears to be able to reach the full Internet.

	switch connectivityState {
	case 0:
		return StatusUnknown, nil
	case 1:
		return StatusOffline, nil
	case 2:
		return StatusPortal, nil
	case 3:
		return StatusLimited, nil
	case 4:
		return StatusOnline, nil
	}

	return StatusUnknown, nil
}

func networkManagerBus() (*dbus.Conn, error) {
	dbusConnLock.Lock()
	defer dbusConnLock.Unlock()
	var err error
	if dbusConn == nil {
		dbusConn, err = dbus.SystemBus()
	}
	return dbusConn, err
}

func getNetworkManagerProperty(conn *dbus.Conn, objectPath dbus.ObjectPath, property string) (dbus.Variant, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return getNetworkManagerPropertyContext(ctx, conn, objectPath, property)
}

func getNetworkManagerPropertyContext(ctx context.Context, conn *dbus.Conn, objectPath dbus.ObjectPath, property string) (dbus.Variant, error) {
	var value dbus.Variant
	separator := strings.LastIndexByte(property, '.')
	if separator < 1 {
		return value, errors.New("invalid NetworkManager property")
	}
	err := conn.Object("org.freedesktop.NetworkManager", objectPath).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", dbus.FlagNoAutoStart, property[:separator], property[separator+1:]).Store(&value)
	return value, err
}

func objectPathInSlice(a dbus.ObjectPath, list []dbus.ObjectPath) bool {
	for _, b := range list {
		if string(b) == string(a) {
			return true
		}
	}
	return false
}
