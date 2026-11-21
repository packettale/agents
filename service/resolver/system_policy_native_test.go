package resolver

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/packettale/agents/service/netenv"
)

func TestNativeSystemDNSRoutingSnapshotSelection(t *testing.T) {
	namespace := os.Getenv("PACKETTALE_TEST_DNS_ROUTING_NAMESPACE")
	if namespace == "" {
		t.Skip("requires a controlled OS private DNS namespace")
	}
	expected := net.ParseIP(os.Getenv("PACKETTALE_TEST_DNS_ROUTING_SERVER"))
	if expected == nil {
		t.Fatal("expected upstream must be an IP address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	configuration, err := netenv.DNSConfiguration(ctx)
	if err != nil {
		t.Fatal("native DNS routing discovery", err)
	}
	preserveDNSResolverState(t)
	loadResolversWithSystemDNS(func(context.Context) (netenv.SystemDNSConfiguration, error) { return configuration, nil })
	q := &Query{FQDN: "snapshot-probe." + strings.Trim(namespace, ".") + ".", QType: dns.Type(dns.TypeA)}
	if !q.check() {
		t.Fatal("invalid controlled namespace")
	}
	selected, source, tryAll := GetResolversInScope(context.Background(), q)
	if len(selected) == 0 || source != ServerSourceOperatingSystem || tryAll {
		t.Fatalf("native private route not selected: source=%s count=%d tryAll=%v", source, len(selected), tryAll)
	}
	for _, r := range selected {
		if !r.Info.IP.Equal(expected) {
			t.Fatalf("native private route included unrelated upstream %s", r.Info.IP)
		}
	}
	// Discovery and selection only: no query is sent for the synthetic name.
}
