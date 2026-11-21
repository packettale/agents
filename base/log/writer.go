package log

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

const (
	logRetention      = 30 * 24 * time.Hour
	logSegmentSize    = 10 * 1024 * 1024
	logNameTimeFormat = "2006-01-02_15-04-05"
)

var ownedLogName = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:-\d+)?\.log$`)

// GlobalWriter is the global log writer.
var GlobalWriter *LogWriter

type LogWriter struct {
	writeLock sync.Mutex
	isStdout  bool
	file      *os.File
	dir       string
	day       string
	size      int64
	closed    bool
	stop      chan struct{}
	done      chan struct{}
}

// NewStdoutWriter creates a log writer for standard output.
func NewStdoutWriter() *LogWriter { return &LogWriter{file: os.Stdout, isStdout: true} }

// NewFileWriter creates private, uniquely named UTC log segments. Segments rotate
// at 10 MiB or the next UTC day; closed segments are retained for 30 days.
func NewFileWriter(dir string) (*LogWriter, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &LogWriter{dir: dir, stop: make(chan struct{}), done: make(chan struct{})}
	now := time.Now()
	if err := l.rotateLocked(now); err != nil {
		return nil, err
	}
	if err := l.cleanLocked(now); err != nil {
		fmt.Fprintf(os.Stderr, "log: retention cleanup failed: %v\n", err)
	}
	go l.maintain()
	return l, nil
}

func (l *LogWriter) rotateLocked(now time.Time) error {
	stem := now.UTC().Format(logNameTimeFormat)
	for suffix := 0; ; suffix++ {
		name := stem
		if suffix > 0 {
			name = fmt.Sprintf("%s-%d", stem, suffix)
		}
		file, err := os.OpenFile(filepath.Join(l.dir, name+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		previous := l.file
		l.file, l.size, l.day = file, 0, now.UTC().Format("2006-01-02")
		if previous != nil {
			return previous.Close()
		}
		return nil
	}
}

func (l *LogWriter) maintain() {
	defer close(l.done)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-ticker.C:
			l.writeLock.Lock()
			if !l.closed {
				if l.day != now.UTC().Format("2006-01-02") {
					if err := l.rotateLocked(now); err != nil {
						fmt.Fprintf(os.Stderr, "log: rotation failed: %v\n", err)
					}
				}
				if err := l.cleanLocked(now); err != nil {
					fmt.Fprintf(os.Stderr, "log: retention cleanup failed: %v\n", err)
				}
			}
			l.writeLock.Unlock()
		}
	}
}

// Write serializes both logging frontends against rotation and shutdown.
func (l *LogWriter) Write(buf []byte) (int, error) {
	if l == nil {
		return 0, errors.New("log writer not initialized")
	}
	l.writeLock.Lock()
	defer l.writeLock.Unlock()
	return l.writeLocked(buf, time.Now())
}

func (l *LogWriter) writeLocked(buf []byte, now time.Time) (int, error) {
	if l.closed {
		return 0, os.ErrClosed
	}
	var rotationErr error
	if !l.isStdout && (l.day != now.UTC().Format("2006-01-02") || l.size > 0 && l.size+int64(len(buf)) > logSegmentSize) {
		rotationErr = l.rotateLocked(now)
	}
	// If opening the next segment fails, keep writing to the existing file.
	n, err := l.file.Write(buf)
	l.size += int64(n)
	return n, errors.Join(rotationErr, err)
}

// WriteMessage writes a formatted message to the writer.
func (l *LogWriter) WriteMessage(msg Message, duplicates uint64) {
	if l == nil {
		return
	}
	l.writeLock.Lock()
	defer l.writeLock.Unlock()
	line := formatLine(msg.(*logLine), duplicates, l.isStdout) + "\n"
	if _, err := l.writeLocked([]byte(line), time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "log: write failed: %v\n", err)
	}
}

func (l *LogWriter) IsStdout() bool { return l != nil && l.isStdout }

// Close stops retention maintenance and closes the file after pending writes.
func (l *LogWriter) Close() {
	if l == nil || l.isStdout {
		return
	}
	l.writeLock.Lock()
	if !l.closed {
		l.closed = true
		close(l.stop)
		_ = l.file.Close()
	}
	l.writeLock.Unlock()
	<-l.done
}

// cleanLocked only removes this logger's regular, inactive segments. Other files,
// directories and symbolic links in a configured log directory are left alone.
func (l *LogWriter) cleanLocked(now time.Time) error {
	files, err := os.ReadDir(l.dir)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range files {
		path := filepath.Join(l.dir, entry.Name())
		if !ownedLogName.MatchString(entry.Name()) || path == l.file.Name() || !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !info.Mode().IsRegular() || !info.ModTime().Before(now.Add(-logRetention)) {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
