package netenv

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

var (
	dnsOLE32               = windows.NewLazySystemDLL("ole32.dll")
	dnsEnableCancellation  = dnsOLE32.NewProc("CoEnableCallCancellation")
	dnsDisableCancellation = dnsOLE32.NewProc("CoDisableCallCancellation")
	dnsCancelCall          = dnsOLE32.NewProc("CoCancelCall")
	dnsOLEAut32            = windows.NewLazySystemDLL("oleaut32.dll")
	dnsArrayDimensions     = dnsOLEAut32.NewProc("SafeArrayGetDim")
	dnsArrayLowerBound     = dnsOLEAut32.NewProc("SafeArrayGetLBound")
	dnsArrayUpperBound     = dnsOLEAut32.NewProc("SafeArrayGetUBound")
	dnsArrayElement        = dnsOLEAut32.NewProc("SafeArrayGetElement")
)

// Read the installed cmdlet's effective-policy method directly. The OS decides
// local/GPO precedence; registry contents alone are not the effective policy.
func readWindowsNRPTRules(ctx context.Context) ([]DNSRoutingRule, error) {
	var records []windowsDNSPolicy
	err := withWindowsDNSCOM(ctx, func() error {
		locator, err := newDNSOLELocator()
		if err != nil {
			return err
		}
		defer locator.Release()
		service, err := dnsOLEMethod(locator, "ConnectServer", ".", `root\Microsoft\Windows\DNS`)
		if err != nil {
			return err
		}
		defer service.Clear()
		class, err := dnsOLEMethod(service.ToIDispatch(), "Get", "PS_DnsClientNrptPolicy")
		if err != nil {
			return err
		}
		defer class.Clear()
		methods, err := dnsOLEProperty(class.ToIDispatch(), "Methods_")
		if err != nil {
			return err
		}
		defer methods.Clear()
		method, err := dnsOLEMethod(methods.ToIDispatch(), "Item", "Get")
		if err != nil {
			return err
		}
		defer method.Clear()
		definition, err := dnsOLEProperty(method.ToIDispatch(), "InParameters")
		if err != nil {
			return err
		}
		defer definition.Clear()
		input, err := dnsOLEMethod(definition.ToIDispatch(), "SpawnInstance_")
		if err != nil {
			return err
		}
		defer input.Clear()
		if input.ToIDispatch() == nil {
			return errors.New("NRPT method has no input parameters")
		}
		assigned, err := oleutil.PutProperty(input.ToIDispatch(), "Effective", true)
		if assigned != nil {
			assigned.Clear()
		}
		if err != nil {
			return fmt.Errorf("set effective NRPT read: %w", err)
		}
		output, err := dnsOLEMethod(service.ToIDispatch(), "ExecMethod", "PS_DnsClientNrptPolicy", "Get", input.ToIDispatch())
		if err != nil {
			return err
		}
		defer output.Clear()
		// Windows returns a null dispatch (not an output object) for an empty table.
		if output.VT != ole.VT_DISPATCH {
			return errors.New("unexpected effective NRPT result type")
		}
		if output.ToIDispatch() == nil {
			return nil
		}
		code, err := dnsOLEProperty(output.ToIDispatch(), "ReturnValue")
		if err != nil {
			return err
		}
		value := code.Value()
		code.Clear()
		if value != uint32(0) && value != int32(0) {
			return fmt.Errorf("effective NRPT method failed: %v", value)
		}
		array, err := dnsOLEProperty(output.ToIDispatch(), "cmdletOutput")
		if err != nil {
			return err
		}
		defer array.Clear()
		return visitDNSOLEArray(array, maxDNSRoutingRules, func(element *ole.VARIANT) error {
			object := element.ToIDispatch()
			if object == nil {
				return errors.New("invalid effective NRPT record")
			}
			record, err := readWindowsDNSPolicy(object)
			if err != nil {
				return err
			}
			records = append(records, record)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return windowsDNSPolicyRules(records)
}

func readWindowsDNSPolicy(object *ole.IDispatch) (windowsDNSPolicy, error) {
	var record windowsDNSPolicy
	namespace, err := dnsOLEProperty(object, "Namespace")
	if err != nil {
		return record, err
	}
	if namespace.VT != ole.VT_BSTR {
		namespace.Clear()
		return record, errors.New("invalid effective NRPT namespace type")
	}
	record.Namespace = namespace.ToString()
	namespace.Clear()
	servers, err := dnsOLEProperty(object, "NameServers")
	if err != nil {
		return record, err
	}
	err = visitDNSOLEArray(servers, maxDNSRouteServers, func(value *ole.VARIANT) error {
		if value.VT != ole.VT_BSTR {
			return errors.New("invalid effective NRPT server type")
		}
		record.NameServers = append(record.NameServers, value.ToString())
		return nil
	})
	servers.Clear()
	if err != nil {
		return record, err
	}
	for _, field := range []struct {
		name   string
		target *bool
	}{
		{"DirectAccessEnabled", &record.DirectAccess},
		{"DnsSecValidationRequired", &record.DNSSECRequired},
		{"DnsSecQueryIPsecRequired", &record.IPsecRequired},
		{"DirectAccessQueryIPsecRequired", &record.IPsecRequired},
	} {
		value, err := dnsOLEProperty(object, field.name)
		if err != nil {
			return record, err
		}
		switch value.VT {
		case ole.VT_EMPTY, ole.VT_NULL:
		case ole.VT_BOOL:
			*field.target = *field.target || value.Value().(bool)
		default:
			value.Clear()
			return record, fmt.Errorf("invalid effective NRPT requirement type: %s", field.name)
		}
		value.Clear()
	}
	return record, nil
}

// Bound cross-process COM calls without starting PowerShell or another agent.
// Keep both COM apartments and the calling thread alive until cancellation has
// stopped; canceling a recycled thread ID could otherwise affect unrelated work.
func withWindowsDNSCOM(parent context.Context, operation func() error) error {
	if err := parent.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	for _, proc := range []*windows.LazyProc{dnsEnableCancellation, dnsDisableCancellation, dnsCancelCall} {
		if err := proc.Find(); err != nil {
			return err
		}
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := initializeDNSCOM(); err != nil {
		return err
	}
	defer ole.CoUninitialize()
	hr, _, _ := dnsEnableCancellation.Call(0)
	if hr != 0 {
		return fmt.Errorf("enable DNS COM cancellation: HRESULT %#x", hr)
	}
	defer dnsDisableCancellation.Call(0) //nolint:errcheck // Synchronous cancellation was enabled above.
	stop, finished := make(chan struct{}), make(chan struct{})
	ready := make(chan error, 1)
	threadID := windows.GetCurrentThreadId()
	go func() {
		defer close(finished)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := initializeDNSCOM(); err != nil {
			ready <- err
			return
		}
		defer ole.CoUninitialize()
		ready <- nil
		select {
		case <-stop:
			return
		case <-ctx.Done():
		}
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			// Retry across gaps between calls until this operation has fully cleaned up.
			dnsCancelCall.Call(uintptr(threadID), 0)
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { close(stop); <-finished }()
	if err := <-ready; err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := operation()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func initializeDNSCOM() error {
	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	var oleErr *ole.OleError
	if errors.As(err, &oleErr) && oleErr.Code() == 1 {
		return nil
	} // S_FALSE: matching apartment already initialized.
	return err
}

func newDNSOLELocator() (*ole.IDispatch, error) {
	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return nil, err
	}
	if unknown == nil {
		return nil, errors.New("DNS COM locator unavailable")
	}
	defer unknown.Release()
	return unknown.QueryInterface(ole.IID_IDispatch)
}

func dnsOLEMethod(receiver *ole.IDispatch, name string, args ...interface{}) (*ole.VARIANT, error) {
	if receiver == nil {
		return nil, fmt.Errorf("DNS COM method %s has no receiver", name)
	}
	value, err := oleutil.CallMethod(receiver, name, args...)
	if err != nil {
		if value != nil {
			value.Clear()
		}
		return nil, fmt.Errorf("DNS COM method %s: %w", name, err)
	}
	if value == nil {
		return nil, fmt.Errorf("DNS COM method %s has no result", name)
	}
	return value, nil
}

func dnsOLEProperty(receiver *ole.IDispatch, name string) (*ole.VARIANT, error) {
	if receiver == nil {
		return nil, fmt.Errorf("DNS COM property %s has no receiver", name)
	}
	value, err := oleutil.GetProperty(receiver, name)
	if err != nil {
		if value != nil {
			value.Clear()
		}
		return nil, fmt.Errorf("DNS COM property %s: %w", name, err)
	}
	if value == nil {
		return nil, fmt.Errorf("DNS COM property %s has no value", name)
	}
	return value, nil
}

// Visit copied SAFEARRAY elements while their VARIANT owns its COM reference.
// The existing generic ToValueArray clears embedded objects before returning;
// retaining those pointers would be unsafe. Never allow an element to escape.
func visitDNSOLEArray(value *ole.VARIANT, limit int, visit func(*ole.VARIANT) error) error {
	if value.VT == ole.VT_EMPTY || value.VT == ole.VT_NULL {
		return nil
	}
	if value.VT&ole.VT_ARRAY == 0 || value.Val == 0 {
		return errors.New("invalid DNS COM array")
	}
	array := value.ToArray()
	if array == nil {
		return errors.New("missing DNS COM array")
	}
	dimensions, _, _ := dnsArrayDimensions.Call(uintptr(unsafe.Pointer(array.Array)))
	if dimensions != 1 {
		return errors.New("DNS COM array must have one dimension")
	}
	kind, err := array.GetType()
	if err != nil {
		return err
	}
	if ole.VT(kind) != ole.VT_VARIANT && ole.VT(kind) != ole.VT_BSTR {
		return errors.New("unsupported DNS COM array element type")
	}
	var lower, upper int32
	for _, bound := range []struct {
		proc   *windows.LazyProc
		target *int32
	}{{dnsArrayLowerBound, &lower}, {dnsArrayUpperBound, &upper}} {
		hr, _, _ := bound.proc.Call(uintptr(unsafe.Pointer(array.Array)), 1, uintptr(unsafe.Pointer(bound.target)))
		if hr != 0 {
			return fmt.Errorf("DNS COM array bound: HRESULT %#x", hr)
		}
	}
	count := int64(upper) - int64(lower) + 1
	if count < 0 || count > int64(limit) {
		return errors.New("DNS COM array exceeds size limit")
	}
	for offset := int64(0); offset < count; offset++ {
		index := int32(int64(lower) + offset)
		var element ole.VARIANT
		var destination unsafe.Pointer
		if ole.VT(kind) == ole.VT_VARIANT {
			destination = unsafe.Pointer(&element)
		} else {
			element.VT = ole.VT_BSTR
			destination = unsafe.Pointer(&element.Val)
		}
		hr, _, _ := dnsArrayElement.Call(uintptr(unsafe.Pointer(array.Array)), uintptr(unsafe.Pointer(&index)), uintptr(destination))
		if hr != 0 {
			element.Clear()
			return fmt.Errorf("DNS COM array element: HRESULT %#x", hr)
		}
		err := visit(&element)
		element.Clear()
		if err != nil {
			return err
		}
	}
	return nil
}
