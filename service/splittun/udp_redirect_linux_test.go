//go:build linux

package splittun

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/packettale/agents/service/splittun/proxy"
)

func TestRedirectedUDPRepliesKeepDestinationAddress(t *testing.T) {
	for _, tc := range []struct {
		name, network, ip string
		ipv6              bool
	}{
		{"IPv4", "udp4", "127.0.0.17", false}, {"IPv6", "udp6", "::1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			echo, err := net.ListenUDP(tc.network, &net.UDPAddr{IP: net.ParseIP(tc.ip)})
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 512)
				n, addr, e := echo.ReadFromUDP(buf)
				if e == nil {
					_, _ = echo.WriteToUDP(buf[:n], addr)
				}
			}()
			defer func() { echo.Close(); <-done }()
			cfg := proxy.DefaultConfig()
			cfg.ReadTimeout = time.Second
			server, err := proxy.NewUDPProxyWithConfig(udpListenAddress(tc.ipv6, 0), tc.network,
				func(local, peer net.Addr) (net.IP, uint16, *proxy.LocalBinding, any, error) {
					a := echo.LocalAddr().(*net.UDPAddr)
					return a.IP, uint16(a.Port), nil, nil, nil
				}, nil, cfg, "test")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if e := server.Shutdown(ctx); e != nil {
					t.Error(e)
				}
			}()
			// Connect to the redirect address, as the kernel does after DNAT. Replies
			// from another local address are rejected by a connected UDP socket.
			address := server.Addr().(*net.UDPAddr)
			if !address.IP.Equal(net.ParseIP(tc.ip)) {
				t.Fatalf("proxy bound %s, want %s", address.IP, tc.ip)
			}
			conn, err := net.DialUDP(tc.network, nil, &net.UDPAddr{IP: net.ParseIP(tc.ip), Port: address.Port})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			payload := []byte("redirected datagram")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 512)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], payload) {
				t.Fatalf("incorrect reply: %q", buf[:n])
			}
		})
	}
}
