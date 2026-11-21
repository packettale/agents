package filterlists

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/tevino/abool"

	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/netenv"
	"github.com/packettale/agents/service/updates"
)

const (
	filterlistsDisabled          = "filterlists:disabled"
	filterlistsUpdateFailed      = "filterlists:update-failed"
	filterlistsStaleDataSurvived = "filterlists:staledata"
)

type FilterLists struct {
	mgr      *mgr.Manager
	instance instance

	states *mgr.StateMgr
}

func (fl *FilterLists) Manager() *mgr.Manager {
	return fl.mgr
}

func (fl *FilterLists) States() *mgr.StateMgr {
	return fl.states
}

func (fl *FilterLists) Start() error {
	return start()
}

func (fl *FilterLists) Stop() error {
	return stop()
}

var (
	// booleans mainly used to decouple the module during testing.
	ignoreUpdateEvents = abool.New()
	ignoreNetEnvEvents = abool.New()
)

func init() {
	ignoreNetEnvEvents.Set()
}

func registerEventCallbacks() {
	module.instance.IntelUpdates().EventResourcesUpdated.AddCallback("Check for blocklist updates",
		func(wc *mgr.WorkerCtx, s struct{}) (bool, error) {
			if ignoreUpdateEvents.IsSet() {
				return false, nil
			}

			return false, tryListUpdate(wc.Ctx())
		})

	module.instance.NetEnv().EventOnlineStatusChange.AddCallback("Check for blocklist updates",
		func(wc *mgr.WorkerCtx, s netenv.OnlineStatus) (bool, error) {
			if ignoreNetEnvEvents.IsSet() {
				return false, nil
			}
			// Nothing to do if we went offline.
			if s == netenv.StatusOffline {
				return false, nil
			}

			return false, tryListUpdate(wc.Ctx())
		})
}

func start() error {
	filterListLock.Lock()
	defer filterListLock.Unlock()

	// Any call of tryListUpdate() must be only after module fully initialized
	defer func() {
		// Register event callbacks
		registerEventCallbacks()

		// Initial check filterlists updates
		module.Manager().Go("intel/filterlists initial check for update", func(ctx *mgr.WorkerCtx) error {
			if err := tryListUpdate(ctx.Ctx()); err != nil {
				log.Errorf("intel/filterlists: tryListUpdate() failed: %q", err.Error())
				return err
			}
			return nil
		})
	}()

	ver, err := getCacheDatabaseVersion()
	if err == nil {
		log.Debugf("intel/filterlists: cache database has version %s", ver.String())

		if err = defaultFilter.loadFromCache(); err != nil {
			err = fmt.Errorf("failed to initialize bloom filters: %w", err)
		}
	}

	if err != nil {
		log.Debugf("intel/filterlists: blocklists disabled, waiting for update (%s)", err)
		warnAboutDisabledFilterLists()
	} else {
		log.Debugf("intel/filterlists: using cache database")
		close(filterListsLoaded)
	}

	return nil
}

func stop() error {
	filterListsLoaded = make(chan struct{})
	return nil
}

func warnAboutDisabledFilterLists() {
	module.states.Add(mgr.State{
		ID:      filterlistsDisabled,
		Name:    "Filter Lists Are Initializing",
		Message: "Filter lists are being downloaded and set up in the background. They will be activated as configured when finished.",
		Type:    mgr.StateTypeWarning,
	})
}

var (
	module     *FilterLists
	shimLoaded atomic.Bool
)

// New returns a new FilterLists module.
func New(instance instance) (*FilterLists, error) {
	if !shimLoaded.CompareAndSwap(false, true) {
		return nil, errors.New("only one instance allowed")
	}
	m := mgr.New("FilterLists")
	module = &FilterLists{
		mgr:      m,
		instance: instance,

		states: mgr.NewStateMgr(m),
	}
	return module, nil
}

type instance interface {
	IntelUpdates() *updates.Updater
	NetEnv() *netenv.NetEnv
}

// Ready reports whether configured list lookups can use a completed cache.
func (fl *FilterLists) Ready() bool { return isLoaded() }

// HealthState distinguishes initialization and failed list processing.
func (fl *FilterLists) HealthState() string {
	for _, state := range fl.states.Export().States {
		if state.ID == filterlistsUpdateFailed || state.ID == filterlistsStaleDataSurvived {
			return "failed"
		}
	}
	if isLoaded() {
		return "ready"
	}
	return "initializing"
}

// Updating reports background cache processing after resources are installed.
func (fl *FilterLists) Updating() bool { return updateInProgress.IsSet() }
