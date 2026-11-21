package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tevino/abool"

	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/base/notifications"
	"github.com/packettale/agents/base/utils/debug"
	_ "github.com/packettale/agents/service/core/base"
	"github.com/packettale/agents/service/intel"
	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/netenv"
)

// ResolverModule is the DNS resolver module.
type ResolverModule struct { //nolint
	mgr      *mgr.Manager
	instance instance

	failingResolverWorkerMgr   *mgr.WorkerMgr
	suggestUsingStaleCacheTask *mgr.WorkerMgr

	isDisabled atomic.Bool

	states *mgr.StateMgr
}

// Manager returns the module manager.
func (rm *ResolverModule) Manager() *mgr.Manager {
	return rm.mgr
}

// States returns the module state manager.
func (rm *ResolverModule) States() *mgr.StateMgr {
	return rm.states
}

// Start starts the module.
func (rm *ResolverModule) Start() error {
	return start()
}

// Stop stops the module.
func (rm *ResolverModule) Stop() error {
	return nil
}

func (rm *ResolverModule) IsDisabled() bool {
	return rm.isDisabled.Load()
}

func prep() error {
	// Set DNS test connectivity function for the online status check
	netenv.DNSTestQueryFunc = func(ctx context.Context, fdqn string) (ips []net.IP, ok bool, err error) {
		return testConnectivity(ctx, fdqn, nil)
	}

	intel.SetReverseResolver(ResolveIPAndValidate)

	if err := registerAPI(); err != nil {
		return err
	}

	if err := prepEnvResolver(); err != nil {
		return err
	}

	return prepConfig()
}

func start() error {
	// load resolvers from config and environment
	loadResolvers()

	// reload after network change
	module.instance.NetEnv().EventNetworkChange.AddCallback(
		"update nameservers",
		func(_ *mgr.WorkerCtx, _ struct{}) (bool, error) {
			loadResolvers()
			log.Debug("resolver: reloaded nameservers due to network change")
			return false, nil
		},
	)

	// reload after config change
	module.instance.Config().EventConfigChange.AddCallback(
		"update nameservers",
		resolverConfigChangeCallback(loadResolvers))

	// Check failing resolvers regularly and when the network changes.
	module.failingResolverWorkerMgr = module.mgr.NewWorkerMgr("check failing resolvers", checkFailingResolvers, nil)
	module.failingResolverWorkerMgr.Go()
	module.instance.NetEnv().EventNetworkChange.AddCallback(
		"check failing resolvers",
		func(wc *mgr.WorkerCtx, _ struct{}) (bool, error) {
			return false, checkFailingResolvers(wc)
		})

	module.suggestUsingStaleCacheTask = module.mgr.NewWorkerMgr("suggest using stale cache", suggestUsingStaleCacheTask, nil)
	module.suggestUsingStaleCacheTask.Go()

	module.mgr.Go(
		"mdns handler",
		listenToMDNS,
	)

	module.mgr.Go("name record delayed cache writer", recordDatabase.DelayedCacheWriter)
	module.mgr.Go("ip info delayed cache writer", ipInfoDatabase.DelayedCacheWriter)

	return nil
}

var localAddrFactory func(network string) net.Addr

// SetLocalAddrFactory supplies the intel package with a function to get permitted local addresses for connections.
func SetLocalAddrFactory(laf func(network string) net.Addr) {
	if localAddrFactory == nil {
		localAddrFactory = laf
	}
}

func getLocalAddr(network string) net.Addr {
	if localAddrFactory != nil {
		return localAddrFactory(network)
	}
	return nil
}

var (
	failingResolverNotification     *notifications.Notification
	failingResolverNotificationSet  = abool.New()
	failingResolverNotificationLock sync.Mutex

	failingResolverErrorID = "resolver:all-configured-resolvers-failed"
)

func notifyAboutFailingResolvers() {
	failingResolverNotificationLock.Lock()
	defer failingResolverNotificationLock.Unlock()
	failingResolverNotificationSet.Set()

	// Check if already set.
	if failingResolverNotification != nil {
		return
	}

	// Create new notification.
	n := &notifications.Notification{
		EventID: failingResolverErrorID,
		Type:    notifications.Error,
		Title:   "Configured DNS Servers Failing",
		Message: `All configured DNS servers in packettale are failing.

You might not be able to connect to these servers, or all of these servers are offline.  
Choosing different DNS servers might fix this problem.

While the issue persists, packettale will use DNS servers from your system or network if policy permits.

Another firewall or secure DNS application might also be interfering. Contact your administrator if this continues.

This notification will go away when packettale detects a working configured DNS server.`,
		AvailableActions: []*notifications.Action{{
			Text: "Change DNS Servers",
			Type: notifications.ActionTypeOpenSetting,
			Payload: &notifications.ActionTypeOpenSettingPayload{
				Key: CfgOptionNameServersKey,
			},
		}},
	}
	notifications.Notify(n)

	failingResolverNotification = n
	n.SyncWithState(module.states)
}

func resetFailingResolversNotification() {
	if failingResolverNotificationSet.IsNotSet() {
		return
	}

	failingResolverNotificationLock.Lock()
	defer failingResolverNotificationLock.Unlock()

	// Remove the notification.
	if failingResolverNotification != nil {
		failingResolverNotification.Delete()
		failingResolverNotification = nil
	}

	// Additionally, resolve the module error, if not done through the notification.
	module.states.Remove(failingResolverErrorID)
}

// AddToDebugInfo adds the system status to the given debug.Info.
func AddToDebugInfo(di *debug.Info) {
	resolversLock.Lock()
	defer resolversLock.Unlock()

	content := make([]string, 0, (len(globalResolvers)*4)-1)
	var working, total int
	for i, resolver := range globalResolvers {
		// Count for summary.
		total++
		failing := resolver.Conn.IsFailing()
		if !failing {
			working++
		}

		// Add section.
		content = append(content, resolver.Info.DescriptiveName())
		content = append(content, fmt.Sprintf("  %s", resolver.Info.ID()))
		if resolver.SearchOnly {
			content = append(content, "  Used for search domains only!")
		}
		if len(resolver.Search) > 0 {
			content = append(content, fmt.Sprintf("  Search Domains: %v", strings.Join(resolver.Search, ", ")))
		}
		if resolver.LinkLocalUnavailable {
			content = append(content, "  Link-local, but not available: ignoring")
		}
		content = append(content, fmt.Sprintf("  Failing: %v", resolver.Conn.IsFailing()))

		// Add a empty line for all but the last entry.
		if i+1 < len(globalResolvers) {
			content = append(content, "")
		}
	}

	di.AddSection(
		fmt.Sprintf("Resolvers: %d/%d", working, total),
		debug.UseCodeSection|debug.AddContentLineBreaks,
		content...,
	)
}

var (
	module     *ResolverModule
	shimLoaded atomic.Bool
)

// New returns a new Resolver module.
func New(instance instance) (*ResolverModule, error) {
	if !shimLoaded.CompareAndSwap(false, true) {
		return nil, errors.New("only one instance allowed")
	}
	m := mgr.New("Resolver")
	module = &ResolverModule{
		mgr:      m,
		instance: instance,

		states: mgr.NewStateMgr(m),
	}
	if err := prep(); err != nil {
		return nil, err
	}
	return module, nil
}

type instance interface {
	NetEnv() *netenv.NetEnv
	Config() *config.Config
}
