//go:build !server

package netenv

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type networkManagerDNSPolicyFixture struct{}

func (networkManagerDNSPolicyFixture) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != "org.freedesktop.NetworkManager.DnsManager" {
		return nil, dbus.MakeFailedError(context.Canceled)
	}
	return map[string]dbus.Variant{
		"Mode": dbus.MakeVariant("default"),
		"Configuration": dbus.MakeVariant([]map[string]dbus.Variant{{
			"nameservers": dbus.MakeVariant([]string{"10.20.0.53"}),
			"domains":     dbus.MakeVariant([]string{"~corp.policy-fixture.com"}),
			"priority":    dbus.MakeVariant(int32(-50)),
			"interface":   dbus.MakeVariant("tun0"), "vpn": dbus.MakeVariant(true),
		}}),
	}, nil
}

func TestNetworkManagerPolicySnapshotUsesDNSManager(t *testing.T) {
	server, client := privateNetworkBus(t)
	if _, err := server.RequestName("org.freedesktop.NetworkManager", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	if err := server.Export(networkManagerDNSPolicyFixture{}, "/org/freedesktop/NetworkManager/DnsManager", "org.freedesktop.DBus.Properties"); err != nil {
		t.Fatal(err)
	}
	dbusConnLock.Lock()
	previous := dbusConn
	dbusConn = client
	dbusConnLock.Unlock()
	t.Cleanup(func() {
		dbusConnLock.Lock()
		dbusConn = previous
		dbusConnLock.Unlock()
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	configuration, err := getDNSConfigurationFromDbusContext(ctx)
	if err != nil || len(configuration.Rules) != 2 {
		t.Fatalf("effective DnsManager policy not read: %+v %v", configuration, err)
	}
	for _, rule := range configuration.Rules {
		if len(rule.Servers) != 1 || !rule.Servers[0].Equal(net.ParseIP("10.20.0.53")) {
			t.Fatalf("policy snapshot included an unrelated resolver: %+v", rule)
		}
	}
}
