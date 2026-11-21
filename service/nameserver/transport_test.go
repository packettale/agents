package nameserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vm "github.com/VictoriaMetrics/metrics"
	"github.com/miekg/dns"
	"github.com/packettale/agents/base/metrics"
	"github.com/packettale/agents/base/notifications"
	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/nameserver/nsutil"
	"github.com/packettale/agents/service/network/packet"
)

var metricsOnce sync.Once

func prepareTransportMetrics(t *testing.T) {
	t.Helper()
	metricsOnce.Do(func() {
		// Use real counters without starting unrelated host metric collectors.
		set := vm.NewSet()
		requestsHistogram = &metrics.Histogram{Histogram: set.NewHistogram("test_dns_request_seconds")}
		totalHandledRequests = &metrics.Counter{Counter: set.NewCounter("test_dns_requests_total")}
	})
}

type transportWriter struct {
	remote  net.Addr
	message *dns.Msg
	errors  []error
	writes  int
	closed  bool
}

func (w *transportWriter) LocalAddr() net.Addr  { return w.remote }
func (w *transportWriter) RemoteAddr() net.Addr { return w.remote }
func (w *transportWriter) WriteMsg(message *dns.Msg) error {
	w.message = message.Copy()
	w.writes++
	if len(w.errors) >= w.writes {
		return w.errors[w.writes-1]
	}
	return nil
}
func (w *transportWriter) Write(body []byte) (int, error) { return len(body), nil }
func (w *transportWriter) Close() error                   { w.closed = true; return nil }
func (w *transportWriter) TsigStatus() error              { return nil }
func (w *transportWriter) TsigTimersOnly(bool)            {}
func (w *transportWriter) Hijack()                        {}

func TestHandlerAcceptsTCPDNSQueries(t *testing.T) {
	prepareTransportMetrics(t)
	request := new(dns.Msg)
	request.SetQuestion("transport.localhost.", dns.TypeA)
	writer := &transportWriter{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42001}}
	if err := handleRequest(context.Background(), writer, request); err != nil {
		t.Fatal(err)
	}
	if writer.message == nil || writer.message.Rcode != dns.RcodeSuccess || len(writer.message.Answer) != 1 {
		t.Fatalf("TCP localhost question did not reach the normal handler: %+v", writer.message)
	}
}

func TestTCPRetainsExternalQueryRestriction(t *testing.T) {
	prepareTransportMetrics(t)
	before := networkServiceMode
	networkServiceMode = func() bool { return false }
	t.Cleanup(func() { networkServiceMode = before })
	for _, addr := range []net.Addr{
		&net.TCPAddr{IP: net.ParseIP("203.0.113.249"), Port: 42001},
		&net.UDPAddr{IP: net.ParseIP("203.0.113.249"), Port: 42001},
		&net.UnixAddr{Name: "unsupported", Net: "unix"},
	} {
		request := new(dns.Msg)
		request.SetQuestion("transport.example.test.", dns.TypeA)
		writer := &transportWriter{remote: addr}
		if err := handleRequest(context.Background(), writer, request); err != nil {
			t.Fatal(err)
		}
		if writer.message == nil || writer.message.Rcode != dns.RcodeRefused {
			t.Fatalf("external/unsupported request %T was not refused: %v", addr, writer.message)
		}
	}
}

func TestTCPQueryIdentityDoesNotCoalesceReusedMessageIDs(t *testing.T) {
	started := time.Now()
	ip := net.IPv4(127, 0, 0, 1)
	first := dnsRequestID(ip, 42001, 17, "same.example.test.A", packet.TCP, started)
	second := dnsRequestID(ip, 42001, 17, "same.example.test.A", packet.TCP, started)
	if first == second {
		t.Fatal("separate TCP queries reused one history identity")
	}
	udpFirst := dnsRequestID(ip, 42001, 17, "same.example.test.A", packet.UDP, started)
	udpRetry := dnsRequestID(ip, 42001, 17, "same.example.test.A", packet.UDP, started.Add(time.Second))
	if udpFirst != udpRetry {
		t.Fatal("existing UDP transaction identity changed")
	}
}

func prepareListenerModule(t *testing.T) {
	t.Helper()
	prepareTransportMetrics(t)
	manager := mgr.New("DNS transport test")
	before := module
	stopListenersLock.Lock()
	beforeStopped, beforeFuncs := stopListeners, stopListenerFuncs
	stopListeners = false
	stopListenerFuncs = make(map[string]func() error)
	stopListenersLock.Unlock()
	module = &NameServer{mgr: manager, states: mgr.NewStateMgr(manager)}
	t.Cleanup(func() {
		_ = stop()
		manager.Cancel()
		if !manager.WaitForWorkers(time.Second) {
			t.Error("DNS workers did not stop")
		}
		module = before
		stopListenersLock.Lock()
		stopListeners, stopListenerFuncs = beforeStopped, beforeFuncs
		stopListenersLock.Unlock()
	})
}

func waitForTransportAnswer(t *testing.T, transport, address string) {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion("transport.localhost.", dns.TypeA)
	client := &dns.Client{Net: transport, Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for {
		answer, _, err := client.Exchange(request, address)
		if err == nil {
			if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
				t.Fatalf("%s answer: %+v", transport, answer)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s DNS listener unavailable: %v", transport, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDNSListenerServesBothTransportsAndStops(t *testing.T) {
	prepareTransportMetrics(t)
	// Reserve a port available on both protocols before starting the real module
	// listener workers. This test never binds the machine's DNS service port.
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(tcp.Addr().(*net.TCPAddr).Port)
	udp, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	_ = udp.Close()
	_ = tcp.Close()
	prepareListenerModule(t)
	startListener(net.IPv4(127, 0, 0, 1), port, true)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for _, transport := range []string{"udp", "tcp"} {
		waitForTransportAnswer(t, transport, address)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"udp", "tcp"} {
		if transport == "udp" {
			listener, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatalf("UDP port not released: %v", err)
			}
			_ = listener.Close()
		} else {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatalf("TCP port not released: %v", err)
			}
			_ = listener.Close()
		}
	}
}

func TestRepliesHonorUDPSizeAndPreserveCompleteTCPAnswer(t *testing.T) {
	answers := make([]dns.RR, 80)
	for index := range answers {
		answers[index] = &dns.SRV{Hdr: dns.RR_Header{Name: "_ldap._tcp.example.test.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}, Port: 389, Target: fmt.Sprintf("directory-server-%03d.example.test.", index)}
	}
	responder := nsutil.ResponderFunc(func(_ context.Context, request *dns.Msg) *dns.Msg {
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Answer = answers
		return reply
	})
	for _, test := range []struct {
		name  string
		tcp   bool
		edns  uint16
		limit int
	}{
		{"plain UDP", false, 0, 512}, {"small EDNS", false, 1, 512},
		{"EDNS1232", false, 1232, 1232}, {"EDNS4096", false, 4096, 4096},
		{"plain TCP", true, 0, 0}, {"TCP ignores UDP limit", true, 512, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := new(dns.Msg)
			request.SetQuestion("_ldap._tcp.example.test.", dns.TypeSRV)
			if test.edns != 0 {
				request.SetEdns0(test.edns, false)
			}
			var remote net.Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42002}
			if test.tcp {
				remote = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42002}
			}
			writer := &transportWriter{remote: remote}
			if err := sendResponse(context.Background(), writer, request, responder); err != nil {
				t.Fatal(err)
			}
			wire, err := writer.message.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if test.tcp {
				if writer.message.Truncated || len(writer.message.Answer) != 80 {
					t.Fatal("TCP answer was truncated")
				}
			} else if len(wire) > test.limit || (len(writer.message.Answer) < 80 && !writer.message.Truncated) {
				t.Fatalf("UDP answer bytes=%d, TC=%v; limit=%d", len(wire), writer.message.Truncated, test.limit)
			}
			if len(answers) != 80 || answers[79].(*dns.SRV).Target != "directory-server-079.example.test." {
				t.Fatal("complete shared answer changed")
			}
		})
	}
}

func TestUDPSendRetryReportsSuccessfulFallback(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("transport.localhost.", dns.TypeA)
	writer := &transportWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42003}, errors: []error{errors.New("first write failed"), nil}}
	if err := sendResponse(context.Background(), writer, request, nsutil.Localhost()); err != nil {
		t.Fatalf("retry succeeded but reported failure: %v", err)
	}
	if writer.writes != 2 {
		t.Fatalf("write attempts=%d", writer.writes)
	}
}

func TestFailedTCPWriteClosesStreamWithoutRetry(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("transport.localhost.", dns.TypeA)
	failed := errors.New("partial TCP write")
	writer := &transportWriter{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42004}, errors: []error{failed}}
	err := sendResponse(context.Background(), writer, request, nsutil.Localhost())
	if !errors.Is(err, failed) || writer.writes != 1 || !writer.closed {
		t.Fatalf("failed TCP stream: writes=%d closed=%v error=%v", writer.writes, writer.closed, err)
	}
}

func TestTCPListenerClearsOnlyItsErrorsAfterSuccessfulBind(t *testing.T) {
	prepareListenerModule(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.Close()
	for _, id := range []string{eventIDListenerFailed, eventIDListenerFailed + "-tcp", eventIDConflictingService + "-tcp"} {
		module.states.Add(mgr.State{ID: id, Name: "previous bind failure", Type: mgr.StateTypeError})
	}
	startTransportListener(net.IPv4(127, 0, 0, 1), port, true, "tcp")
	waitForTransportAnswer(t, "tcp", address)
	states := module.states.Export().States
	if len(states) != 1 || states[0].ID != eventIDListenerFailed {
		t.Fatalf("TCP success must clear its old failures and retain UDP error: %+v", states)
	}
}

func TestIPv6ListenerAndPersistentTCPQueries(t *testing.T) {
	prepareListenerModule(t)
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	address := listener.Addr().String()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.Close()
	startListener(net.IPv6loopback, port, false)
	waitForTransportAnswer(t, "udp", address)
	waitForTransportAnswer(t, "tcp", address)
	client := &dns.Client{Net: "tcp", Timeout: time.Second}
	connection, err := client.Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	for index := range 3 {
		request := new(dns.Msg)
		request.SetQuestion(fmt.Sprintf("query-%d.localhost.", index), dns.TypeAAAA)
		request.Id = 17
		answer, _, err := client.ExchangeWithConn(request, connection)
		if err != nil || answer == nil || answer.Id != 17 || len(answer.Answer) != 1 || answer.Question[0].Name != request.Question[0].Name {
			t.Fatalf("persistent TCP query %d: answer=%v error=%v", index, answer, err)
		}
	}
}

func TestStopDuringListenerStartupDoesNotLeaveSockets(t *testing.T) {
	for index := range 20 {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			prepareListenerModule(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			port := uint16(listener.Addr().(*net.TCPAddr).Port)
			_ = listener.Close()
			startListener(net.IPv4(127, 0, 0, 1), port, true)
			// Manager.Go registers workers asynchronously. Wait until both have
			// entered this module before replacing its package-global test fixture.
			// The bind/NotifyStarted/stop ordering remains concurrent.
			deadline := time.Now().Add(time.Second)
			for {
				stopListenersLock.Lock()
				registered := len(stopListenerFuncs)
				stopListenersLock.Unlock()
				if registered == 2 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("listener workers did not enter module")
				}
				time.Sleep(time.Microsecond)
			}
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			module.mgr.Cancel()
			if !module.mgr.WaitForWorkers(time.Second) {
				t.Fatal("listener workers still active")
			}
			tcp, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatalf("late TCP socket after stop: %v", err)
			}
			defer tcp.Close()
			udp, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatalf("late UDP socket after stop: %v", err)
			}
			defer udp.Close()
		})
	}
}

func TestTCPBindFailurePreservesUDPAndRecovers(t *testing.T) {
	// Exercise the real notification/state path without constructing the rest
	// of the service or introducing a listener-error hook into production.
	notifier, err := notifications.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := notifier.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		notifier.Manager().Cancel()
		notifier.Manager().WaitForWorkers(time.Second)
	})
	prepareListenerModule(t)
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	address := blocker.Addr().String()
	port := uint16(blocker.Addr().(*net.TCPAddr).Port)
	startListener(net.IPv4(127, 0, 0, 1), port, true)
	waitForTransportAnswer(t, "udp", address)
	deadline := time.Now().Add(time.Second)
	for {
		states := module.states.Export().States
		if len(states) == 1 && states[0].ID == eventIDListenerFailed+"-tcp" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("TCP bind failure not independently reported: %+v", states)
		}
		time.Sleep(time.Millisecond)
	}
	waitForTransportAnswer(t, "udp", address)
	_ = blocker.Close()
	deadline = time.Now().Add(4 * time.Second)
	for len(module.states.Export().States) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("TCP listener did not recover: %+v", module.states.Export().States)
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitForTransportAnswer(t, "tcp", address)
	waitForTransportAnswer(t, "udp", address)
}

func TestNonReadingTCPClientCannotHoldShutdownOpen(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	_ = reservation.Close()
	ready := make(chan struct{})
	var entered, completed atomic.Int32
	server := &dns.Server{Addr: address, Net: "tcp", NotifyStartedFunc: func() { close(ready) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			entered.Add(1)
			answer := new(dns.Msg)
			answer.SetReply(q)
			for range 220 {
				answer.Answer = append(answer.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 30}, Txt: []string{strings.Repeat("x", 240)}})
			}
			_ = writeDNSResponse(context.Background(), w, q, answer)
			completed.Add(1)
		})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- serveDNSListener(server) }()
	select {
	case <-ready:
	case err := <-serveDone:
		t.Fatalf("serve failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("listener did not start")
	}
	client, err := net.DialTCP("tcp", nil, server.Listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Shutdown() })
	_ = client.SetReadBuffer(1024)
	_ = client.SetWriteDeadline(time.Now().Add(time.Second))
	connection := &dns.Conn{Conn: client}
	for range 128 {
		request := new(dns.Msg)
		request.SetQuestion("large.example.test.", dns.TypeTXT)
		if err := connection.WriteMsg(request); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		before := entered.Load()
		if before > completed.Load() {
			time.Sleep(100 * time.Millisecond)
			if entered.Load() == before && completed.Load() < before {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture did not produce a blocked response write")
		}
		time.Sleep(time.Millisecond)
	}
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- server.Shutdown() }()
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("non-reading TCP client held shutdown open beyond write deadline")
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve worker still active after shutdown")
	}
}

func TestTCPCompressesCompleteAnswerAboveUncompressedWireLimit(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("_ldap._tcp.example.test.", dns.TypeSRV)
	response := new(dns.Msg)
	response.SetReply(request)
	for index := range 700 {
		response.Answer = append(response.Answer, &dns.SRV{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 30}, Port: 389, Target: fmt.Sprintf("server-%04d.%s.example.test.", index, strings.Repeat("a", 40))})
	}
	if response.Len() <= dns.MaxMsgSize {
		t.Fatal("fixture must exceed uncompressed wire limit")
	}
	writer := &transportWriter{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42005}}
	if err := writeDNSResponse(context.Background(), writer, request, response); err != nil {
		t.Fatal(err)
	}
	wire, err := writer.message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > dns.MaxMsgSize || len(writer.message.Answer) != 700 || writer.message.Truncated || !writer.message.Compress {
		t.Fatalf("TCP full reply not compressed below protocol limit: bytes=%d answers=%d TC=%v compressed=%v", len(wire), len(writer.message.Answer), writer.message.Truncated, writer.message.Compress)
	}
	if response.Compress || len(response.Answer) != 700 {
		t.Fatal("shared original message changed")
	}
}
