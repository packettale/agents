package netenv

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestReadResolvconf(t *testing.T) {
	for _, test := range []struct {
		name, input string
		ips, search []string
	}{
		{"whitespace and comments", " # comment\n nameserver\t10.20.0.53 # primary\nnameserver  fd00::53 ; secondary\nsearch\tcorp.example   branch.example\t# ignored.example\n", []string{"10.20.0.53", "fd00::53"}, []string{"corp.example", "branch.example"}},
		{"last search directive wins", "search old.example\ndomain new.example\nnameserver 10.0.0.53\n", []string{"10.0.0.53"}, []string{"new.example"}},
		{"invalid entries", "nameserver bad\nnameserver\nnameserver 10.0.0.53\nsearch . bad..example good.example\n", []string{"10.0.0.53"}, []string{"good.example"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			servers, err := readResolvconf(strings.NewReader(test.input))
			if err != nil || len(servers) != len(test.ips) {
				t.Fatalf("servers=%v error=%v", servers, err)
			}
			for i, server := range servers {
				if server.IP.String() != test.ips[i] || !reflect.DeepEqual(server.Search, test.search) {
					t.Errorf("server[%d]=%v, want %s %v", i, server, test.ips[i], test.search)
				}
			}
		})
	}
}

type failingDNSReader struct{}

func (failingDNSReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestReadResolvconfReportsReadError(t *testing.T) {
	if _, err := readResolvconf(failingDNSReader{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error lost: %v", err)
	}
}

func TestLinuxEnvironment(t *testing.T) {
	t.Parallel()

	nameserversTest, err := getNameserversFromResolvconf()
	if err != nil {
		t.Errorf("failed to get namerservers from resolvconf: %s", err)
	}
	t.Logf("nameservers from resolvconf: %+v", nameserversTest)
}
