//go:build !server

package netenv

import (
	"context"
	"testing"

	"github.com/godbus/dbus/v5"
)

type resolvedLinkPathFixture struct{}

func (resolvedLinkPathFixture) GetLink(index int32) (dbus.ObjectPath, *dbus.Error) {
	if index != 7 {
		return "", dbus.MakeFailedError(context.Canceled)
	}
	return "/org/freedesktop/resolve1/link/returned_path", nil
}

type resolvedLinkRouteFixture struct{}

func (resolvedLinkRouteFixture) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != "org.freedesktop.resolve1.Link" {
		return nil, dbus.MakeFailedError(context.Canceled)
	}
	return map[string]dbus.Variant{"DefaultRoute": dbus.MakeVariant(true), "DNSSEC": dbus.MakeVariant("no"), "DNSOverTLS": dbus.MakeVariant("no")}, nil
}

func TestResolvedDefaultRouteUsesReturnedLinkPath(t *testing.T) {
	client, _, _ := slowNetworkManagerBus(t)
	if _, err := client.RequestName("org.freedesktop.resolve1", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	if err := client.Export(resolvedLinkPathFixture{}, "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager"); err != nil {
		t.Fatal(err)
	}
	if err := client.Export(resolvedLinkRouteFixture{}, "/org/freedesktop/resolve1/link/returned_path", "org.freedesktop.DBus.Properties"); err != nil {
		t.Fatal(err)
	}
	enabled, err := resolvedLinkDefaultRoute(context.Background(), client, 7)
	if err != nil || !enabled {
		t.Fatalf("OS-returned link path was not used: enabled=%v error=%v", enabled, err)
	}
}
