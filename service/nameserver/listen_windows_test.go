package nameserver

import (
	"context"
	"net"
	"strconv"
	"testing"
)

func TestExclusiveDNSListenerRejectsShadowedWildcard(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		other, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		port := other.LocalAddr().(*net.UDPAddr).Port
		config := dnsListenConfig()
		conn, err := config.ListenPacket(context.Background(), "udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
		if err == nil {
			conn.Close()
			t.Fatal("wildcard bound despite another DNS listener owning the redirect target")
		}
	})
	t.Run("tcp", func(t *testing.T) {
		other, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		port := other.Addr().(*net.TCPAddr).Port
		config := dnsListenConfig()
		conn, err := config.Listen(context.Background(), "tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
		if err == nil {
			conn.Close()
			t.Fatal("wildcard bound despite another DNS listener owning the redirect target")
		}
	})
}
