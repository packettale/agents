package resolver

import (
	"reflect"
	"testing"
)

func TestResolverParsingDoesNotMutatePublishedBootstrapDomains(t *testing.T) {
	resolversLock.Lock()
	before := resolverInitDomains
	resolverInitDomains = map[string]struct{}{"retained.policy-fixture.com.": {}}
	resolversLock.Unlock()
	t.Cleanup(func() { resolversLock.Lock(); resolverInitDomains = before; resolversLock.Unlock() })
	if _, _, err := createResolver("dot://new.policy-fixture.com?ip=192.0.2.53", ServerSourceConfigured); err != nil {
		t.Fatal(err)
	}
	resolversLock.RLock()
	unchanged := reflect.DeepEqual(resolverInitDomains, map[string]struct{}{"retained.policy-fixture.com.": {}})
	resolversLock.RUnlock()
	if !unchanged {
		t.Fatal("validation changed the currently published bootstrap-domain map")
	}
}

func TestResolverBootstrapDomainsBelongToTheCurrentSnapshot(t *testing.T) {
	hostname, _, err := createResolver("dot://DNS.policy-fixture.com?ip=192.0.2.53", ServerSourceConfigured)
	if err != nil {
		t.Fatal(err)
	}
	static, _, err := createResolver("dot://192.0.2.54?verify=static.policy-fixture.com", ServerSourceConfigured)
	if err != nil {
		t.Fatal(err)
	}
	if got := makeResolverBootstrapDomains([]*Resolver{hostname, static}); !reflect.DeepEqual(got, map[string]struct{}{"dns.policy-fixture.com.": {}}) {
		t.Fatalf("wrong bootstrap source set: %+v", got)
	}
	if got := makeResolverBootstrapDomains([]*Resolver{static}); len(got) != 0 {
		t.Fatal("removed resolver domain stayed active")
	}
}
