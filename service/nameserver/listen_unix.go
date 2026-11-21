//go:build !windows

package nameserver

import "net"

func dnsListenConfig() net.ListenConfig { return net.ListenConfig{} }
