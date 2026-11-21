package log

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileWriterRotatesAndCopiesActiveFile(t *testing.T) {
	dir := t.TempDir()
	l, err := NewFileWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	first := l.file.Name()
	data := bytes.Repeat([]byte("a"), logSegmentSize)
	if _, err := l.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	second := l.file.Name()
	if first == second {
		t.Fatal("size limit did not rotate")
	}
	if got, err := os.ReadFile(first); err != nil || !bytes.Equal(got, data) {
		t.Fatal("rotated segment lost data", err)
	}
	// Exercise a separate reader and destination while the writer remains open,
	// including on native Windows. No running service needs to be stopped.
	got, err := os.ReadFile(second)
	if err != nil || string(got) != "next" {
		t.Fatal("cannot read active file", err)
	}
	if err := os.WriteFile(filepath.Join(t.TempDir(), "copied.log"), got, 0o600); err != nil {
		t.Fatal(err)
	}
	l.writeLock.Lock()
	_, err = l.writeLocked([]byte("tomorrow"), time.Now().Add(24*time.Hour))
	third := l.file.Name()
	l.writeLock.Unlock()
	if err != nil || third == second {
		t.Fatal("day boundary did not rotate", err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(third)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe permissions: %v", info.Mode())
		}
	}
}

func TestFileWriterNeverOverwritesAndStopsMaintenance(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	existing := filepath.Join(dir, now.UTC().Format(logNameTimeFormat)+".log")
	if err := os.WriteFile(existing, []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := NewFileWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l.file.Name() == existing {
		t.Fatal("reused existing file")
	}
	if got, _ := os.ReadFile(existing); string(got) != "retained" {
		t.Fatal("existing file truncated")
	}
	l.Close()
	l.Close()
	select {
	case <-l.done:
	default:
		t.Fatal("maintenance outlived writer")
	}
	if _, err := l.Write([]byte("closed")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestFileWriterRetentionProtectsOtherAndActiveFiles(t *testing.T) {
	dir := t.TempDir()
	l, err := NewFileWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Now()
	old := now.Add(-31 * 24 * time.Hour)
	files := []string{"2000-01-01_00-00-00.log", "2000-01-01_00-00-00-1.log", "unrelated.log", "notes.txt", "2000-01-02_00-00-00.log"}
	for _, name := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		stamp := old
		if name == files[4] {
			stamp = now
		}
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(l.file.Name(), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "2000-01-03_00-00-00.log"), 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(dir, "notes.txt"), filepath.Join(dir, "2000-01-04_00-00-00.log")); err != nil {
			t.Fatal(err)
		}
	}
	l.writeLock.Lock()
	err = l.cleanLocked(now)
	l.writeLock.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for n, name := range files {
		_, err := os.Stat(filepath.Join(dir, name))
		if n < 2 && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired segment retained: %s", name)
		}
		if n >= 2 && err != nil {
			t.Fatalf("unrelated/recent file removed: %s", name)
		}
	}
	if _, err := os.Stat(l.file.Name()); err != nil {
		t.Fatal("active file removed", err)
	}
}

func TestFileWriterConcurrentWritesAndRotationFailure(t *testing.T) {
	l, err := NewFileWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := fmt.Fprintf(l, "%d:%d\n", i, j); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
	got, err := os.ReadFile(l.file.Name())
	if err != nil || bytes.Count(got, []byte("\n")) != 1600 {
		t.Fatal("lost concurrent records", err)
	}
	l.writeLock.Lock()
	originalDir := l.dir
	l.dir = filepath.Join(l.dir, "missing")
	n, err := l.writeLocked([]byte("rotation-fallback"), time.Now().Add(24*time.Hour))
	l.dir = originalDir
	l.writeLock.Unlock()
	if err == nil || n != len("rotation-fallback") {
		t.Fatal("rotation failure did not retain record and report error", n, err)
	}
	got, _ = os.ReadFile(l.file.Name())
	if !bytes.HasSuffix(got, []byte("rotation-fallback")) {
		t.Fatal("rotation failure lost record")
	}
}

func TestDiagnosticTimeIncludesUTCOffset(t *testing.T) {
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.FixedZone("test", 5*60*60))
	line := formatLine(&logLine{timestamp: at, level: InfoLevel, msg: "test"}, 0, false)
	if !strings.Contains(line, "10:00:00.000+05:00") {
		t.Fatalf("ambiguous timestamp: %s", line)
	}
}
