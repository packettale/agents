package netenv

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// InterfaceAddress is a current address on an active non-loopback interface.
type InterfaceAddress struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
}

// AssignedInterfaceAddresses reuses the network-change-aware interface cache.
// It performs no discovery requests and is not called on the packet path.
func AssignedInterfaceAddresses() ([]InterfaceAddress, error) {
	ifaceCacheLock.Lock()
	defer ifaceCacheLock.Unlock()
	if err := ensureIfaceCache(); err != nil {
		return nil, err
	}
	return interfaceAddressRows(ifaceCache), nil
}

func interfaceAddressRows(entries []cachedNetInterface) []InterfaceAddress {
	rows := make([]InterfaceAddress, 0)
	seen := make(map[InterfaceAddress]bool)
	for _, entry := range entries {
		name := entry.iface.Name
		if len(name) == 0 || len(name) > 255 || !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) {
			continue
		}
		for _, ip := range entry.addrs {
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			row := InterfaceAddress{Interface: name, Address: ip.String()}
			if !seen[row] {
				rows = append(rows, row)
				seen[row] = true
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Interface != rows[j].Interface {
			return rows[i].Interface < rows[j].Interface
		}
		return rows[i].Address < rows[j].Address
	})
	if len(rows) > 64 {
		rows = rows[:64]
	}
	return rows
}
