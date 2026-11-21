//go:build windows

package management

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateJSONDoesNotInheritUsersAccess(t *testing.T) {
	dir := t.TempDir()
	grant := exec.Command("icacls.exe", dir, "/grant", "*S-1-5-32-545:(OI)(CI)(RX)")
	if output, err := grant.CombinedOutput(); err != nil {
		t.Fatalf("grant Users on parent: %v: %s", err, output)
	}
	path := filepath.Join(dir, "credential.json")
	if err := writePrivateJSON(path, map[string]string{"credential": "secret"}); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("icacls.exe", path).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect credential ACL: %v: %s", err, output)
	}
	acl := string(output)
	if strings.Contains(acl, `BUILTIN\Users`) || strings.Contains(acl, `Everyone`) || strings.Contains(acl, `Authenticated Users`) {
		t.Fatalf("credential inherits broad read access: %s", acl)
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatalf("administrators cannot read credential: %v", err)
	}
}

func TestStartSecuresExistingCredential(t *testing.T) {
	dir := t.TempDir()
	grant := exec.Command("icacls.exe", dir, "/grant", "*S-1-5-32-545:(OI)(CI)(RX)")
	if output, err := grant.CombinedOutput(); err != nil {
		t.Fatalf("grant Users on parent: %v: %s", err, output)
	}
	path := filepath.Join(dir, stateFile)
	if err := os.WriteFile(path, []byte(`{"credential":"secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := New(dir, nil).Start(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("icacls.exe", path).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect existing credential ACL: %v: %s", err, output)
	}
	if strings.Contains(string(output), `BUILTIN\Users`) {
		t.Fatalf("existing credential still readable by Users: %s", output)
	}
}
