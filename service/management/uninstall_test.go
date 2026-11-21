package management

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUninstallRejectsUnscopedCredentialAndRemoteCommandArguments(t *testing.T) {
	c := New(t.TempDir(), nil)
	c.SetServiceReady(true)
	for _, test := range []struct {
		name, token string
		extra       bool
	}{
		{"missing", "", false}, {"short", "secret", false}, {"injected", strings.Repeat("a", 43), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var data map[string]any
			_ = json.Unmarshal(operationData(c, "uninstall_keep_history"), &data)
			data["completion_token"] = test.token
			if test.extra {
				data["uninstaller"] = "other.exe"
			}
			body, _ := json.Marshal(data)
			if err := c.handleOperation(context.Background(), testOperationClock(), body, func(any) error { return nil }); err == nil {
				t.Fatal("unsafe uninstall command accepted")
			}
		})
	}
}

func TestUninstallRefusesAnUnownedTestBinaryAndReportsFailure(t *testing.T) {
	c := New(t.TempDir(), nil)
	c.SetServiceReady(true)
	var command map[string]any
	_ = json.Unmarshal(operationData(c, "uninstall_keep_history"), &command)
	command["completion_token"] = strings.Repeat("a", 43)
	body, _ := json.Marshal(command)
	statuses := make(chan string, 3)
	if err := c.handleOperation(context.Background(), testOperationClock(), body, func(value any) error { statuses <- value.(map[string]string)["status"]; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"accepted", "failed"} {
		select {
		case actual := <-statuses:
			if actual != expected {
				t.Fatalf("got %s want %s", actual, expected)
			}
		case <-time.After(time.Second):
			t.Fatal("missing uninstall status")
		}
	}
	if err := c.handleOperation(context.Background(), testOperationClock(), body, func(value any) error {
		if value.(map[string]string)["status"] != "failed" {
			t.Error("replayed uninstall changed status")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestUninstallWorkerRejectsPathsOutsideItsPrivateDirectory(t *testing.T) {
	for _, path := range []string{"request.json", filepath.Join(t.TempDir(), "request.json")} {
		if err := RunUninstallWorker(path); err == nil {
			t.Fatal("untrusted uninstall request accepted")
		}
	}
}
