//go:build !server

package netenv

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type slowNetworkProperties struct {
	release <-chan struct{}
	entered chan struct{}
}

func (p *slowNetworkProperties) Get(string, string) (dbus.Variant, *dbus.Error) {
	select {
	case p.entered <- struct{}{}:
	default:
	}
	<-p.release
	return dbus.MakeVariant(uint32(0)), nil
}

func privateNetworkBus(t *testing.T) (*dbus.Conn, *dbus.Conn) {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("requires dbus-daemon")
	}
	output, err := exec.Command("dbus-daemon", "--session", "--fork", "--address=unix:path="+filepath.Join(t.TempDir(), "bus.sock"), "--print-address=1", "--print-pid=1").Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(output))
	if len(lines) != 2 {
		t.Fatalf("unexpected private bus output: %q", output)
	}
	pid, err := strconv.Atoi(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p, _ := os.FindProcess(pid); _ = p.Kill() })
	server, err := dbus.Connect(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := dbus.Connect(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

func slowNetworkManagerBus(t *testing.T) (*dbus.Conn, chan struct{}, chan struct{}) {
	t.Helper()
	server, client := privateNetworkBus(t)
	if _, err := server.RequestName("org.freedesktop.NetworkManager", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	t.Cleanup(func() { close(release) })
	if err := server.Export(&slowNetworkProperties{release, entered}, "/org/freedesktop/NetworkManager", "org.freedesktop.DBus.Properties"); err != nil {
		t.Fatal(err)
	}
	return client, release, entered
}

func TestNetworkManagerPropertyReadIsBounded(t *testing.T) {
	client, _, _ := slowNetworkManagerBus(t)
	done := make(chan error, 1)
	go func() {
		_, err := getNetworkManagerProperty(client, "/org/freedesktop/NetworkManager", "org.freedesktop.NetworkManager.PrimaryConnection")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("missing discovery deadline: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Error("unresponsive NetworkManager blocked the network monitor")
	}
}

func TestNetworkManagerPropertyReadObservesCallerCancellation(t *testing.T) {
	client, _, entered := slowNetworkManagerBus(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := getNetworkManagerPropertyContext(ctx, client, "/org/freedesktop/NetworkManager", "org.freedesktop.NetworkManager.PrimaryConnection")
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("test RPC did not reach slow service")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("network monitor cancellation was ignored")
	}
}
