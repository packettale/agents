package nameserver

import (
	"net"
	"syscall"
)

// SO_EXCLUSIVEADDRUSE prevents a wildcard listener from sharing port 53 with
// a more specific Windows DNS listener that would receive redirected traffic.
const soExclusiveAddrUse = -5

func dnsListenConfig() net.ListenConfig {
	return net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		err := raw.Control(func(fd uintptr) {
			optionErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soExclusiveAddrUse, 1)
		})
		if err != nil {
			return err
		}
		return optionErr
	}}
}
