package dbmodule

import (
	"time"

	"github.com/packettale/agents/base/database"
	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/service/mgr"
)

func startMaintenanceTasks() {
	_ = module.mgr.Repeat("basic maintenance", 10*time.Minute, maintainBasic)
	_ = module.mgr.Repeat("thorough maintenance", 1*time.Hour, maintainThorough)
	_ = module.mgr.Repeat("record maintenance", 1*time.Hour, maintainRecords)
}

func maintainBasic(ctx *mgr.WorkerCtx) error {
	log.Infof("database: running Maintain")
	return database.Maintain(ctx.Ctx())
}

func maintainThorough(ctx *mgr.WorkerCtx) error {
	log.Infof("database: running MaintainThorough")
	return database.MaintainThorough(ctx.Ctx())
}

func maintainRecords(ctx *mgr.WorkerCtx) error {
	log.Infof("database: running MaintainRecordStates")
	return database.MaintainRecordStates(ctx.Ctx())
}
