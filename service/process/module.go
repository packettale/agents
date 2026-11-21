package process

import (
	"errors"
	"sync/atomic"

	"github.com/packettale/agents/service/mgr"
)

type ProcessModule struct {
	mgr *mgr.Manager
}

func (pm *ProcessModule) Manager() *mgr.Manager {
	return pm.mgr
}

func (pm *ProcessModule) Start() error {
	return nil
}

func (pm *ProcessModule) Stop() error {
	return nil
}

func prep() error {
	if err := registerConfiguration(); err != nil {
		return err
	}

	if err := registerAPIEndpoints(); err != nil {
		return err
	}

	return nil
}

var (
	module     *ProcessModule
	shimLoaded atomic.Bool
)

// New returns a new Process module.
func New() (*ProcessModule, error) {
	if !shimLoaded.CompareAndSwap(false, true) {
		return nil, errors.New("only one instance allowed")
	}

	m := mgr.New("ProcessModule")
	module = &ProcessModule{
		mgr: m,
	}

	if err := prep(); err != nil {
		return nil, err
	}
	return module, nil
}
