package interception

import (
	"strings"
	"testing"
)

func TestDNSRedirectRulesCoverBothTransports(t *testing.T) {
	for _, test := range []struct {
		name   string
		rules  []string
		target string
	}{
		{"IPv4", v4rules, "127.0.0.17:53"}, {"IPv6", v6rules, "[::1]:53"},
	} {
		for _, protocol := range []string{"udp", "tcp"} {
			found := false
			for _, rule := range test.rules {
				if strings.Contains(rule, "--mark 1799 ") && strings.Contains(rule, "-p "+protocol+" ") && strings.HasSuffix(rule, "-j DNAT --to "+test.target) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s DNS redirect has no %s DNAT target", test.name, protocol)
			}
		}
	}
}
