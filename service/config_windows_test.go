package service

import (
	"slices"
	"testing"
)

func TestWindowsBinaryUpdatesRetainInstalledLegalNotice(t *testing.T) {
	binary, _, err := MakeUpdateConfigs(&ServiceConfig{BinDir: t.TempDir(), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(binary.Ignore, "LICENSE.txt") {
		t.Fatal("binary update removes installed GPL notice")
	}
	if !slices.Contains(binary.Ignore, "uninstall.exe") {
		t.Fatal("binary update removes existing uninstaller")
	}
}
