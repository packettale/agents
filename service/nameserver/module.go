package nameserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/base/notifications"
	"github.com/packettale/agents/service/compat"
	"github.com/packettale/agents/service/firewall"
	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/netenv"
)

type NameServer struct {
	mgr      *mgr.Manager
	instance instance

	states *mgr.StateMgr
}

func (ns *NameServer) Manager() *mgr.Manager {
	return ns.mgr
}

func (ns *NameServer) States() *mgr.StateMgr {
	return ns.states
}

func (ns *NameServer) Start() error {
	return start()
}

func (ns *NameServer) Stop() error {
	return stop()
}

var (
	stopListeners     bool
	stopListenerFuncs = make(map[string]func() error)
	stopListenersLock sync.Mutex

	eventIDConflictingService = "nameserver:conflicting-service"
	eventIDListenerFailed     = "nameserver:listener-failed"
)

func prep() error {
	return registerConfig()
}

func start() error {
	if err := registerMetrics(); err != nil {
		return err
	}

	// Get listen addresses.
	ip1, ip2, port, err := getListenAddresses(nameserverAddressConfig())
	if err != nil {
		return fmt.Errorf("failed to parse nameserver listen address: %w", err)
	}

	firewall.SetNameserverReadyMatcher(listenerReady)

	// Tell the compat module where we are listening.
	compat.SetNameserverListenIP(ip1)

	// Get own hostname.
	hostname, err = os.Hostname()
	if err != nil {
		log.Warningf("nameserver: failed to get hostname: %s", err)
	}
	hostname += "."

	// Start listener(s).
	if ip2 == nil {
		// Start a single listener.
		startListener(ip1, port, true)

		// Set nameserver matcher in firewall to fast-track dns queries.
		if ip1.Equal(net.IPv4zero) || ip1.Equal(net.IPv6zero) {
			// Fast track dns queries destined for any of the local IPs.
			return firewall.SetNameserverIPMatcher(func(ip net.IP) bool {
				dstIsMe, err := netenv.IsMyIP(ip)
				if err != nil {
					log.Warningf("nameserver: failed to check if IP %s is local: %s", ip, err)
				}
				return dstIsMe
			})
		}
		return firewall.SetNameserverIPMatcher(func(ip net.IP) bool {
			return ip.Equal(ip1)
		})
	}

	// Dual listener.
	startListener(ip1, port, true)
	startListener(ip2, port, false)

	// Fast track dns queries destined for one of the listener IPs.
	return firewall.SetNameserverIPMatcher(func(ip net.IP) bool {
		return ip.Equal(ip1) || ip.Equal(ip2)
	})
}

func startListener(ip net.IP, port uint16, first bool) {
	for _, transport := range []string{"udp", "tcp"} {
		startTransportListener(ip, port, first, transport)
	}
}

func startTransportListener(ip net.IP, port uint16, first bool, transport string) {
	// Start DNS server as service worker.
	module.mgr.Go("dns resolver "+transport, func(ctx *mgr.WorkerCtx) error {
		started := make(chan struct{})
		finished := make(chan struct{})
		defer close(finished)
		defer setListenerReady(ip, transport, false)
		// Create DNS server.
		dnsServer := &dns.Server{
			Addr: net.JoinHostPort(
				ip.String(),
				strconv.Itoa(int(port)),
			),
			Net:     transport,
			Handler: dns.HandlerFunc(handleRequestAsWorker),
			NotifyStartedFunc: func() {
				setListenerReady(ip, transport, true)
				// Report recovery only after the socket actually binds. A healthy
				// UDP listener must not hide a TCP failure (or vice versa).
				if first {
					suffix := listenerEventSuffix(transport, first)
					module.states.Remove(eventIDListenerFailed + suffix)
					module.states.Remove(eventIDConflictingService + suffix)
				}
				close(started)
			},
		}

		// Register stop function.
		func() {
			stopListenersLock.Lock()
			defer stopListenersLock.Unlock()

			// Check if we should stop
			if stopListeners {
				dnsServer = nil
				return
			}

			// Register stop function.
			// Bind retries replace the same entry, keeping ownership bounded.
			key := transport + "/" + ip.String()
			stopListenerFuncs[key] = func() error {
				// A shutdown racing the initial bind waits for either successful
				// startup or a completed bind failure, never leaving a late socket.
				select {
				case <-finished:
					return nil
				case <-started:
					return dnsServer.Shutdown()
				}
			}
		}()

		// Check if we should stop.
		if dnsServer == nil {
			return nil
		}

		// Start listening.
		log.Infof("nameserver: starting to listen on %s/%s", dnsServer.Addr, transport)
		err := serveDNSListener(dnsServer)
		if err != nil {
			// Stop worker without error if we are shutting down.
			if module.mgr.IsDone() {
				return nil
			}
			log.Warningf("nameserver: failed to listen on %s: %s", dnsServer.Addr, err)
			handleListenError(err, ip, port, first, transport)
		}
		return err
	})
}

func listenerEventSuffix(transport string, primary bool) string {
	suffix := ""
	if transport == "tcp" {
		suffix = "-tcp"
	}
	if !primary {
		suffix += "-secondary"
	}
	return suffix
}

func serveDNSListener(server *dns.Server) error {
	config := dnsListenConfig()
	if server.Net != "tcp" {
		conn, err := config.ListenPacket(context.Background(), "udp", server.Addr)
		if err != nil {
			return err
		}
		defer conn.Close()
		server.PacketConn = conn
		return server.ActivateAndServe()
	}
	listener, err := config.Listen(context.Background(), "tcp", server.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	server.Listener = &dnsTCPListener{Listener: listener}
	return server.ActivateAndServe()
}

type dnsTCPListener struct{ net.Listener }

func (l *dnsTCPListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &dnsTCPConn{Conn: conn}, nil
}

type dnsTCPConn struct{ net.Conn }

func (c *dnsTCPConn) Write(data []byte) (int, error) {
	// miekg/dns v1.1.68 documents a two-second write timeout, but does not
	// apply it to server connections. Bound writes so slow readers cannot
	// hold a request worker (and graceful shutdown) indefinitely.
	if err := c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return 0, err
	}
	return c.Conn.Write(data)
}

func handleListenError(err error, ip net.IP, port uint16, primaryListener bool, transport string) {
	var n *notifications.Notification

	// Create suffix for secondary listener
	secondaryEventIDSuffix := listenerEventSuffix(transport, primaryListener)

	// Find a conflicting service.
	cfProcess := findConflictingProcess(ip, port, transport)
	if cfProcess != nil {
		// Report the conflicting process.

		// Build conflicting process description.
		var cfDescription string
		cfName, err := cfProcess.Name()
		if err == nil && cfName != "" {
			cfDescription = cfName
		}
		cfExe, err := cfProcess.Exe()
		if err == nil && cfDescription != "" {
			if cfDescription != "" {
				cfDescription += " (" + cfExe + ")"
			} else {
				cfDescription = cfName
			}
		}

		// Notify user about conflicting service.
		n = notifications.Notify(&notifications.Notification{
			EventID: eventIDConflictingService + secondaryEventIDSuffix,
			Type:    notifications.Error,
			Title:   "Conflicting DNS Software",
			Message: "Restart packettale after you have deactivated or configured the conflicting software: " +
				cfDescription,
		})
	} else {
		// If no conflict is found, report the error directly.
		n = notifications.Notify(&notifications.Notification{
			EventID: eventIDListenerFailed + secondaryEventIDSuffix,
			Type:    notifications.Error,
			Title:   "Secure DNS Error",
			Message: fmt.Sprintf(
				"The internal DNS server (%s) failed. Restart packettale to try again. Error: %s",
				transport, err,
			),
		})
	}

	// Attach error to module, if primary listener.
	if primaryListener {
		n.SyncWithState(module.states)
	}
}

func stop() error {
	stopListenersLock.Lock()

	// Stop listeners.
	stopListeners = true
	listeners := stopListenerFuncs
	stopListenerFuncs = make(map[string]func() error)
	stopListenersLock.Unlock()
	for name, shutdown := range listeners {
		if err := shutdown(); err != nil {
			log.Warningf("nameserver: failed to stop %s: %s", name, err)
		}
	}

	return nil
}

func getListenAddresses(listenAddress string) (ip1, ip2 net.IP, port uint16, err error) {
	// Split host and port.
	ipString, portString, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return nil, nil, 0, fmt.Errorf(
			"failed to parse address %s: %w",
			listenAddress,
			err,
		)
	}

	// Parse the IP address. If the want to listen on localhost, we need to
	// listen separately for IPv4 and IPv6.
	if ipString == "localhost" {
		ip1 = net.IPv4(127, 0, 0, 17)
		if netenv.IPv6Enabled() {
			ip2 = net.IPv6loopback
		} else {
			log.Warningf("nameserver: no IPv6 stack detected, disabling IPv6 nameserver listener")
		}
	} else {
		ip1 = net.ParseIP(ipString)
		if ip1 == nil {
			return nil, nil, 0, fmt.Errorf(
				"failed to parse IP %s from %s",
				ipString,
				listenAddress,
			)
		}
	}

	// Parse the port.
	port64, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, nil, 0, fmt.Errorf(
			"failed to parse port %s from %s: %w",
			portString,
			listenAddress,
			err,
		)
	}

	return ip1, ip2, uint16(port64), nil
}

var (
	module     *NameServer
	shimLoaded atomic.Bool
)

// New returns a new NameServer module.
func New(instance instance) (*NameServer, error) {
	if !shimLoaded.CompareAndSwap(false, true) {
		return nil, errors.New("only one instance allowed")
	}
	m := mgr.New("NameServer")
	module = &NameServer{
		mgr:      m,
		instance: instance,

		states: mgr.NewStateMgr(m),
	}
	if err := prep(); err != nil {
		return nil, err
	}

	return module, nil
}

type instance interface{}
