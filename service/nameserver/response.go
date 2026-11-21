package nameserver

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"

	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/service/nameserver/nsutil"
)

// sendResponse sends a response to query using w. The response message is
// created by responder. If addExtraRRs is not nil and implements the
// RRProvider interface then it will be also used to add more RRs in the
// extra section.
func sendResponse(
	ctx context.Context,
	w dns.ResponseWriter,
	request *dns.Msg,
	responder nsutil.Responder,
	rrProviders ...nsutil.RRProvider,
) error {
	// Have the Responder craft a DNS reply.
	reply := responder.ReplyWithDNS(ctx, request)
	if reply == nil {
		// Dropping query.
		return nil
	}
	// Signify that we are a recursive resolver.
	// While we do not handle recursion directly, we can safely assume, that we
	// always forward to a recursive resolver.
	reply.RecursionAvailable = true

	// Add extra RRs through a custom RRProvider.
	for _, rrProvider := range rrProviders {
		if rrProvider != nil {
			rrs := rrProvider.GetExtraRRs(ctx, request)
			reply.Extra = append(reply.Extra, rrs...)
		}
	}

	// Write reply.
	if err := writeDNSResponse(ctx, w, request, reply); err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	return nil
}

func writeDNSResponse(ctx context.Context, w dns.ResponseWriter, request, m *dns.Msg) (err error) {
	defer func() {
		// recover from panic
		if panicErr := recover(); panicErr != nil {
			err = fmt.Errorf("panic: %s", panicErr)
			log.Tracer(ctx).Debugf("nameserver: panic caused by this msg: %#v", m)
		}
	}()

	_, tcp := w.RemoteAddr().(*net.TCPAddr)
	if tcp {
		// A complete answer can fit the DNS wire limit only when compressed.
		// Copy the message header without changing shared cache records.
		compressed := *m
		compressed.Compress = true
		m = &compressed
	} else {
		size := uint16(dns.MinMsgSize)
		if edns := request.IsEdns0(); edns != nil && edns.UDPSize() > size {
			size = edns.UDPSize()
		}
		if m.Len() > int(size) {
			// Resolver records may be shared with subsequent UDP/TCP requests.
			m = m.Copy()
			m.Truncate(int(size))
		}
	}
	err = w.WriteMsg(m)
	if err != nil {
		if tcp {
			// A partial stream write cannot be retried as another DNS frame.
			_ = w.Close()
			return err
		}
		// If we receive an error we might have exceeded the message size with all
		// our extra information records. Retry again without the extra section.
		log.Tracer(ctx).Tracef("nameserver: retrying to write dns message without extra section, error was: %s", err)
		m.Extra = nil
		noExtraErr := w.WriteMsg(m)
		if noExtraErr != nil {
			return fmt.Errorf("failed to write dns message without extra section: %w", errors.Join(err, noExtraErr))
		}
		return nil
	}
	return
}
