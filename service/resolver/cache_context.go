package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/packettale/agents/service/netenv"
)

// prepareResolverCacheContext initializes fresh resolvers before publication.
// Do not update an already published Info: in-flight requests and cached records
// retain it, so their responses must keep the previous configuration marker.
func prepareResolverCacheContext(resolvers []*Resolver, policy []systemDNSPolicyScope) string {
	type route struct {
		ID, URL, Address, Path, BlockDetection   string
		Search                                   []string
		SearchOnly, SearchExclusive, Unavailable bool
	}
	routes := make([]route, 0, len(resolvers))
	for _, resolver := range resolvers {
		search := append([]string{}, resolver.Search...)
		sort.Strings(search)
		routes = append(routes, route{
			ID: resolver.Info.ID(), URL: resolver.ConfigURL,
			Address: resolver.ServerAddress, Path: resolver.Path,
			BlockDetection: resolver.UpstreamBlockDetection,
			Search:         search, SearchOnly: resolver.SearchOnly,
			SearchExclusive: resolver.SearchExclusive,
			Unavailable:     resolver.LinkLocalUnavailable,
		})
	}
	// This representation contains only strings, bools and slices; JSON encoding
	// cannot fail. Preserve resolver order because it determines query priority.
	rules := make([]netenv.DNSRoutingRule, 0, len(policy))
	for _, scope := range policy {
		rules = append(rules, scope.Rule)
	}
	encoded, _ := json.Marshal(struct {
		Resolvers []route
		Rules     []netenv.DNSRoutingRule
	}{routes, rules})
	digest := sha256.Sum256(encoded)
	context := hex.EncodeToString(digest[:])
	for _, resolver := range resolvers {
		resolver.Info.CacheContext = context
	}
	return context
}
