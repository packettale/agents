package management

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const telemetryOutboxFile = "management-telemetry-outbox.jsonl"

type telemetryOutboxHeader struct {
	Version  int       `json:"version"`
	DeviceID string    `json:"device_id"`
	Hour     time.Time `json:"hour"`
}

type telemetryOutboxFooter struct {
	Complete bool   `json:"complete"`
	Pages    int    `json:"pages"`
	SHA256   string `json:"sha256"`
}

// walkTelemetryOutbox uses at most one compact page in memory. The first pass
// verifies the complete file before any HTTP request; the second sends it.
// The checksum and footer detect damaged or truncated local queue files.
func walkTelemetryOutbox(ctx context.Context, path string, expected *telemetryOutboxHeader, send func(telemetryBatch) error) (telemetryOutboxHeader, error) {
	var header telemetryOutboxHeader
	if err := ctx.Err(); err != nil {
		return header, err
	}
	file, err := os.Open(path)
	if err != nil {
		return header, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	// 1000 pairs of 255-byte labels, including worst-case JSON escaping.
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	if !scanner.Scan() {
		return header, errors.New("telemetry outbox header is missing")
	}
	if err := json.Unmarshal(scanner.Bytes(), &header); err != nil {
		return header, fmt.Errorf("read telemetry outbox header: %w", err)
	}
	if header.Version != 1 || header.DeviceID == "" || header.Hour.IsZero() || !header.Hour.Equal(header.Hour.UTC().Truncate(time.Hour)) {
		return header, errors.New("invalid telemetry outbox header")
	}
	if expected != nil && (header.DeviceID != expected.DeviceID || !header.Hour.Equal(expected.Hour)) {
		return header, errors.New("telemetry outbox identity or hour changed")
	}
	digest := sha256.New()
	pages := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return header, err
		}
		line := scanner.Bytes()
		var batch telemetryBatch
		if err := json.Unmarshal(line, &batch); err != nil {
			return header, fmt.Errorf("read telemetry outbox page: %w", err)
		}
		if batch.BatchID == "" {
			var footer telemetryOutboxFooter
			if err := json.Unmarshal(line, &footer); err != nil || !footer.Complete || pages == 0 || footer.Pages != pages || footer.SHA256 != hex.EncodeToString(digest.Sum(nil)) {
				return header, errors.New("telemetry outbox is incomplete or damaged")
			}
			if scanner.Scan() || scanner.Err() != nil {
				return header, errors.New("unexpected data after telemetry outbox footer")
			}
			return header, nil
		}
		if batch.BatchID != fmt.Sprintf("h2/%s/%d", header.Hour.UTC().Format("20060102T15"), pages) || batch.DestinationMode != "hourly_delta" || len(batch.Destinations) > 1000 {
			return header, errors.New("invalid telemetry outbox page")
		}
		_, _ = digest.Write(line)
		_, _ = digest.Write([]byte{'\n'})
		pages++
		if send != nil {
			if err := send(batch); err != nil {
				return header, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return header, fmt.Errorf("read telemetry outbox: %w", err)
	}
	return header, errors.New("telemetry outbox footer is missing")
}

// prepareTelemetryOutbox freezes all pages before the first upload. Network
// failures and local history cleanup cannot change a batch already accepted by
// the server. It runs only in the management worker, outside packet processing.
func (c *Client) prepareTelemetryOutbox(ctx context.Context, state State, hour time.Time) (telemetryOutboxHeader, error) {
	header := telemetryOutboxHeader{Version: 1, DeviceID: state.DeviceID, Hour: hour.UTC()}
	path := filepath.Join(c.dataDir, telemetryOutboxFile)
	saved, err := walkTelemetryOutbox(ctx, path, nil, nil)
	if err == nil {
		if saved.DeviceID == header.DeviceID && saved.Hour.Equal(header.Hour) {
			return saved, nil
		}
		if saved.DeviceID == header.DeviceID && saved.Hour.After(header.Hour) {
			return header, errors.New("telemetry outbox is ahead of the cursor")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return header, err
	}
	file, err := os.CreateTemp(c.dataDir, ".management-telemetry-*")
	if err != nil {
		return header, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := setPrivateFilePermissions(file); err != nil {
		return header, err
	}
	if err := json.NewEncoder(file).Encode(header); err != nil {
		return header, err
	}
	digest := sha256.New()
	encoder := json.NewEncoder(io.MultiWriter(file, digest))
	pages := 0
	if err := c.collectHour(ctx, hour, func(batch telemetryBatch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := encoder.Encode(batch); err != nil {
			return err
		}
		pages++
		return nil
	}); err != nil {
		return header, err
	}
	footer := telemetryOutboxFooter{Complete: true, Pages: pages, SHA256: hex.EncodeToString(digest.Sum(nil))}
	if err := json.NewEncoder(file).Encode(footer); err != nil {
		return header, err
	}
	if err := file.Sync(); err != nil {
		return header, err
	}
	if err := file.Close(); err != nil {
		return header, err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return header, err
	}
	return header, nil
}

func (c *Client) uploadHour(ctx context.Context, config Config, state State, hour time.Time) error {
	header, err := c.prepareTelemetryOutbox(ctx, state, hour)
	if err != nil {
		return err
	}
	_, err = walkTelemetryOutbox(ctx, filepath.Join(c.dataDir, telemetryOutboxFile), &header, func(batch telemetryBatch) error {
		return c.postTelemetry(ctx, config, state, batch)
	})
	return err
}
