package main

import (
	"debug/pe"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateWindowsIconsForSupportedArchitectures(t *testing.T) {
	dir := t.TempDir()
	if err := generate("../../../assets/data/icons/packettale.ico", dir); err != nil {
		t.Fatal(err)
	}
	for arch, machine := range map[string]uint16{"amd64": pe.IMAGE_FILE_MACHINE_AMD64, "arm64": pe.IMAGE_FILE_MACHINE_ARM64} {
		file, err := pe.Open(filepath.Join(dir, "icon_windows_"+arch+".syso"))
		if err != nil {
			t.Fatal(err)
		}
		if file.Machine != machine || len(file.Sections) == 0 {
			t.Errorf("invalid %s icon resource", arch)
		}
		file.Close()
	}
}

func TestInvalidIconCannotGenerateResources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.ico")
	if err := os.WriteFile(path, []byte("not an icon"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := generate(path, dir); err == nil {
		t.Fatal("invalid icon accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "icon_windows_amd64.syso")); !os.IsNotExist(err) {
		t.Fatal("invalid resource object generated")
	}
}
