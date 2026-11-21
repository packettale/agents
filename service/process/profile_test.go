package process

import (
	"runtime"
	"testing"

	"github.com/packettale/agents/service/profile"
)

func TestServiceOnlyProcessIdentities(t *testing.T) {
	pid := ownPID + 1000
	for _, path := range []string{"packettale.exe", "/usr/bin/packettale", "/usr/bin/browser"} {
		p := &Process{Pid: pid, Path: path, Env: map[string]string{"PACKETTALE_UI_WEBVIEW_PROCESS": "1"}}
		if got := p.getSpecialProfileID(); got != "" {
			t.Fatalf("ordinary process received special identity %q", got)
		}
	}
	if got := (&Process{Pid: ownPID}).getSpecialProfileID(); got != profile.PackettaleProfileID {
		t.Fatalf("core identity lost: %s", got)
	}
	p := &Process{Pid: pid, Path: "/usr/lib/systemd/systemd-resolved"}
	if runtime.GOOS == "windows" {
		p.Path = `C:\Windows\System32\svchost.exe`
		p.CmdLine = "svchost.exe -s Dnscache"
	}
	if got := p.getSpecialProfileID(); got != profile.SystemResolverProfileID {
		t.Fatalf("system DNS identity lost: %s", got)
	}
}
