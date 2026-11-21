package netenv

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-ole/go-ole/oleutil"
)

func TestWindowsNRPTAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readWindowsNRPTRules(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read returned %v", err)
	}
}

func TestWindowsNRPTEffectivePolicyNative(t *testing.T) {
	namespace := os.Getenv("PACKETTALE_TEST_NRPT_NAMESPACE")
	if namespace == "" {
		t.Skip("requires a controlled effective NRPT fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rules, err := readWindowsNRPTRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expected := os.Getenv("PACKETTALE_TEST_NRPT_SERVER")
	expectedExact := os.Getenv("PACKETTALE_TEST_NRPT_EXACT") == "1"
	for _, r := range rules {
		if r.Namespace != namespace {
			continue
		}
		if r.Priority != DNSRoutePolicy || r.Blocked != (os.Getenv("PACKETTALE_TEST_NRPT_BLOCKED") == "1") {
			t.Fatalf("unexpected effective mode: %+v", r)
		}
		if r.Exact != expectedExact {
			t.Fatalf("wrong native exact/suffix mode: %+v", r)
		}
		if r.Blocked {
			return
		}
		if expected == "" {
			if !r.Exempt {
				t.Fatal("expected NRPT exemption")
			}
		} else {
			if len(r.Servers) != 1 || !r.Servers[0].Equal(net.ParseIP(expected)) || r.Exempt {
				t.Fatalf("wrong effective server: %+v", r)
			}
		}
		return
	}
	t.Fatalf("controlled effective NRPT namespace missing: %s", namespace)
}

func TestWindowsDNSCOMCancellationNative(t *testing.T) {
	address := os.Getenv("PACKETTALE_TEST_WMI_CANCEL_ADDRESS")
	if address == "" {
		t.Skip("requires an unused address on an isolated test LAN")
	}
	ip := net.ParseIP(address)
	if ip == nil || !ip.IsPrivate() {
		t.Fatal("controlled cancellation target must be a private IP")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := withWindowsDNSCOM(ctx, func() error {
		unknown, err := newDNSOLELocator()
		if err != nil {
			return err
		}
		defer unknown.Release()
		service, err := dnsOLEMethod(unknown, "ConnectServer", ".", `root\cimv2`)
		if err != nil {
			return err
		}
		defer service.Clear()
		output, err := dnsOLEMethod(service.ToIDispatch(), "ExecQuery", fmt.Sprintf("SELECT * FROM Win32_PingStatus WHERE Address='%s' AND Timeout=10000", ip.String()), "WQL", 0)
		if output != nil {
			output.Clear()
		}
		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("uncanceled native read: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("native cancellation took %s", elapsed)
	}
	// Cancellation must not leave the reused OS thread or COM state poisoned.
	err = withWindowsDNSCOM(context.Background(), func() error {
		locator, err := newDNSOLELocator()
		if err != nil {
			return err
		}
		defer locator.Release()
		service, err := dnsOLEMethod(locator, "ConnectServer", ".", `root\cimv2`)
		if err != nil {
			return err
		}
		defer service.Clear()
		result, err := oleutil.CallMethod(service.ToIDispatch(), "ExecQuery", "SELECT Caption FROM Win32_OperatingSystem", "WQL", 0)
		if result != nil {
			result.Clear()
		}
		return err
	})
	if err != nil {
		t.Fatal("normal read after cancellation", err)
	}
}

func TestWindowsDNSOLERejectsNilReceiver(t *testing.T) {
	if _, err := dnsOLEMethod(nil, "Get"); err == nil {
		t.Fatal("nil COM receiver accepted")
	}
	if _, err := dnsOLEProperty(nil, "Namespace"); err == nil {
		t.Fatal("nil COM receiver accepted")
	}
	if _, err := windowsDNSPolicyRules([]windowsDNSPolicy{{Namespace: strings.Repeat("a.", 150)}}); err == nil {
		t.Fatal("oversized native namespace accepted")
	}
}

func TestWindowsNRPTEmptyNative(t *testing.T) {
	if os.Getenv("PACKETTALE_TEST_NRPT_EMPTY") != "1" {
		t.Skip("requires an empty controlled NRPT fixture")
	}
	rules, err := readWindowsNRPTRules(context.Background())
	if err != nil || len(rules) != 0 {
		t.Fatalf("native empty policy: %+v %v", rules, err)
	}
}
