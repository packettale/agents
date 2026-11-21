package netenv

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/service/network/netutils"
)

var (
	gateways                   = make([]net.IP, 0)
	gatewaysInfo               = make([]GatewayInfo, 0) // same as gateways but with additional info
	gatewaysLock               sync.Mutex
	gatewaysNetworkChangedFlag = GetNetworkChangedFlag()

	nameservers                   = make([]Nameserver, 0)
	nameserversLock               sync.Mutex
	nameserversNetworkChangedFlag = GetNetworkChangedFlag()
)

type GatewayInfo struct {
	IP        net.IP
	Interface string
	Mask      net.IPMask
}

// Gateways returns the currently active gateways.
func Gateways() []net.IP {
	gatewaysLock.Lock()
	defer gatewaysLock.Unlock()
	refreshGatewaysCache()

	return gateways
}

// GatewaysInfo returns the currently active gateways with interface metadata.
func GatewaysInfo() []GatewayInfo {
	gatewaysLock.Lock()
	defer gatewaysLock.Unlock()

	refreshGatewaysCache()

	return gatewaysInfo
}

func refreshGatewaysCache() {
	// Check if the network changed, if not, keep cache.
	if !gatewaysNetworkChangedFlag.IsSet() {
		return
	}
	gatewaysNetworkChangedFlag.Refresh()

	gateways = make([]net.IP, 0)
	gatewaysInfo = make([]GatewayInfo, 0)
	var decoded []byte

	// open file
	route, err := os.Open("/proc/net/route")
	if err != nil {
		log.Warningf("environment: could not read /proc/net/route: %s", err)
		return
	}
	defer func() {
		_ = route.Close()
	}()

	// file scanner
	scanner := bufio.NewScanner(route)
	scanner.Split(bufio.ScanLines)

	// parse
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) < 4 {
			continue
		}
		iface := line[0]
		if line[1] == "00000000" {
			decoded, err = hex.DecodeString(line[2])
			if err != nil {
				log.Warningf("environment: could not parse gateway %s from /proc/net/route: %s", line[2], err)
				continue
			}
			if len(decoded) != 4 {
				log.Warningf("environment: decoded gateway %s from /proc/net/route has wrong length", decoded)
				continue
			}
			gate := net.IPv4(decoded[3], decoded[2], decoded[1], decoded[0])
			mask := net.IPv4Mask(0, 0, 0, 0)
			if len(line) > 7 {
				decodedMask, decodeMaskErr := hex.DecodeString(line[7])
				if decodeMaskErr != nil {
					log.Warningf("environment: could not parse netmask %s from /proc/net/route: %s", line[7], decodeMaskErr)
				} else if len(decodedMask) == 4 {
					mask = net.IPv4Mask(decodedMask[3], decodedMask[2], decodedMask[1], decodedMask[0])
				}
			}
			gateways = append(gateways, gate)
			gatewaysInfo = append(gatewaysInfo, GatewayInfo{IP: gate, Interface: iface, Mask: mask})
		}
	}

	// open file
	v6route, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		log.Warningf("environment: could not read /proc/net/ipv6_route: %s", err)
		return
	}
	defer func() {
		_ = v6route.Close()
	}()

	// file scanner
	scanner = bufio.NewScanner(v6route)
	scanner.Split(bufio.ScanLines)

	// parse
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) < 6 {
			continue
		}
		iface := line[len(line)-1]
		if line[0] == "00000000000000000000000000000000" && line[4] != "00000000000000000000000000000000" {
			mask := net.CIDRMask(0, 128)
			prefixLength, parsePrefixLengthErr := strconv.ParseInt(line[1], 16, 32)
			if parsePrefixLengthErr == nil {
				mask = net.CIDRMask(int(prefixLength), 128)
			}
			decoded, err := hex.DecodeString(line[4])
			if err != nil {
				log.Warningf("environment: could not parse gateway %s from /proc/net/ipv6_route: %s", line[2], err)
				continue
			}
			if len(decoded) != 16 {
				log.Warningf("environment: decoded gateway %s from /proc/net/ipv6_route has wrong length", decoded)
				continue
			}
			gate := net.IP(decoded)
			gateways = append(gateways, gate)
			gatewaysInfo = append(gatewaysInfo, GatewayInfo{IP: gate, Interface: iface, Mask: mask})
		}
	}
}

// Nameservers returns the currently active nameservers.
func Nameservers() []Nameserver {
	nameserversLock.Lock()
	defer nameserversLock.Unlock()
	// Check if the network changed, if not, return cache.
	if !nameserversNetworkChangedFlag.IsSet() {
		return nameservers
	}
	nameserversNetworkChangedFlag.Refresh()

	// logic
	// TODO: try:
	// 1. NetworkManager DBUS
	// 2. /etc/resolv.conf
	// 2.1. if /etc/resolv.conf has localhost nameserver, check for dnsmasq config (are there others?)
	nameservers = make([]Nameserver, 0)

	// get nameservers from DBUS
	dbusNameservers, err := getNameserversFromDbus()
	if err != nil {
		log.Warningf("environment: could not get nameservers from dbus: %s", err)
	} else {
		nameservers = addNameservers(nameservers, dbusNameservers)
	}
	// networkd-based desktops may expose only resolved's loopback stub in
	// resolv.conf. Discover its upstreams instead of querying our own listener.
	if len(nameservers) == 0 {
		resolvedNameservers, err := getNameserversFromResolved()
		if err != nil {
			log.Debugf("environment: could not get nameservers from systemd-resolved: %s", err)
			RetryDNSDiscoveryAfter(30 * time.Second)
		} else {
			nameservers = addNameservers(nameservers, resolvedNameservers)
			if len(resolvedNameservers) == 0 {
				RetryDNSDiscoveryAfter(30 * time.Second)
			}
		}
	}

	// get nameservers from /etc/resolv.conf
	resolvconfNameservers, err := getNameserversFromResolvconf()
	if err != nil {
		log.Warningf("environment: could not get nameservers from resolvconf: %s", err)
	} else {
		nameservers = addNameservers(nameservers, resolvconfNameservers)
	}
	for _, server := range nameservers {
		if server.IP != nil && !server.IP.IsLoopback() && !server.IP.IsUnspecified() && !server.IP.IsMulticast() {
			nameserverDiscoveryRetry.Store(false)
			break
		}
	}

	return nameservers
}

func getNameserversFromResolvconf() ([]Nameserver, error) {
	// open file
	resolvconf, err := os.Open("/etc/resolv.conf")
	if err != nil {
		log.Warningf("environment: could not read /etc/resolv.conf: %s", err)
		return nil, err
	}
	defer func() {
		_ = resolvconf.Close()
	}()
	return readResolvconf(resolvconf)
}

func readResolvconf(reader io.Reader) ([]Nameserver, error) {
	// file scanner
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanLines)

	var searchDomains []string
	var servers []net.IP

	// parse
	for scanner.Scan() {
		text := scanner.Text()
		if i := strings.IndexAny(text, "#;"); i >= 0 {
			text = text[:i]
		}
		line := strings.Fields(text)
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case "search", "domain":
			searchDomains = nil
			values := line[1:]
			if line[0] == "domain" {
				values = values[:1]
			}
			for _, domain := range values {
				if domain != "." && netutils.IsValidFqdn(dns.Fqdn(domain)) {
					searchDomains = append(searchDomains, domain)
				}
			}
		case "nameserver":
			ip := net.ParseIP(line[1])
			if ip != nil {
				servers = append(servers, ip)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// build array
	nameservers := make([]Nameserver, 0, len(servers))
	for _, server := range servers {
		nameservers = append(nameservers, Nameserver{
			IP:     server,
			Search: searchDomains,
		})
	}
	return nameservers, nil
}

func addNameservers(nameservers, newNameservers []Nameserver) []Nameserver {
	for _, newNameserver := range newNameservers {
		found := false
		for i, nameserver := range nameservers {
			if nameserver.IP.Equal(newNameserver.IP) {
				nameservers[i].ScopeOnly = nameservers[i].ScopeOnly && newNameserver.ScopeOnly
				for _, domain := range newNameserver.Search {
					if !slices.Contains(nameservers[i].Search, domain) {
						nameservers[i].Search = append(nameservers[i].Search, domain)
					}
				}
				found = true
				break
			}
		}
		if !found {
			nameservers = append(nameservers, newNameserver)
		}
	}
	return nameservers
}
