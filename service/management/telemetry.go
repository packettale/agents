package management

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/netquery/orm"
)

const cursorFile = "management-telemetry-cursor.json"

type telemetryCursor struct {
	DeviceID string    `json:"device_id"`
	NextHour time.Time `json:"next_hour"`
}

type hourlySummary struct {
	Hour          string `json:"hour"`
	Allowed       int64  `json:"allowed"`
	Blocked       int64  `json:"blocked"`
	DNS           int64  `json:"dns"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
}

type dailyDestination struct {
	Day     string `json:"day"`
	App     string `json:"app"`
	Host    string `json:"host"`
	Allowed int64  `json:"allowed"`
	Blocked int64  `json:"blocked"`
}

type telemetryBatch struct {
	BatchID         string             `json:"batch_id"`
	DestinationMode string             `json:"destination_mode"`
	Hourly          []hourlySummary    `json:"hourly"`
	Destinations    []dailyDestination `json:"destinations"`
}

func boundedLabel(value string) string {
	if value == "" {
		return "Unknown"
	}
	if len(value) <= 255 {
		return value
	}
	hash := sha256.Sum256([]byte(value))
	suffix := "#" + hex.EncodeToString(hash[:8])
	for len(value)+len(suffix) > 255 {
		_, size := utf8.DecodeLastRuneInString(value)
		value = value[:len(value)-size]
	}
	return value + suffix
}

func (c *Client) telemetryLoop(ctx context.Context, config Config, w *mgr.WorkerCtx) {
	var nextApplicationSync time.Time
	var nextTelemetrySync time.Time
	for ctx.Err() == nil {
		if c.applicationCatalogueEnabled.Load() && !time.Now().Before(nextApplicationSync) {
			nextApplicationSync = time.Now().Add(5 * time.Minute)
			if err := c.flushApplicationCatalogue(ctx, config); err != nil && ctx.Err() == nil {
				w.Warn("application catalogue delayed", "err", err)
			}
		}
		if !time.Now().Before(nextTelemetrySync) {
			err := c.flushTelemetry(ctx, config)
			c.summaryUploadDelayed.Store(err != nil)
			delay := time.Minute
			if err == nil && c.compactSummaryActive.Load() {
				delay = 5 * time.Minute
			}
			nextTelemetrySync = time.Now().Add(delay)
			if err != nil && ctx.Err() == nil {
				w.Warn("compact telemetry delayed", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

func (c *Client) flushTelemetry(ctx context.Context, config Config) error {
	state, err := readIdentity(c.dataDir)
	if err != nil {
		return err
	}
	if state.Credential == "" || state.DeviceID == "" {
		return errors.New("device is not enrolled")
	}
	if store, ok := c.store.(CompactSummaryStore); ok {
		ready, err := store.ConfigureCompactSummaries(ctx, state.DeviceID, c.compactSummaryEnabled.Load())
		if err != nil {
			return err
		}
		c.compactSummaryActive.Store(ready)
		if ready {
			return c.flushCompactSummaries(ctx, config, state, store)
		}
	}
	end := time.Now().UTC().Truncate(time.Hour)
	cursor := telemetryCursor{DeviceID: state.DeviceID, NextHour: end.Add(-time.Hour)}
	cursorLoaded := false
	if data, err := os.ReadFile(filepath.Join(c.dataDir, cursorFile)); err == nil {
		var saved telemetryCursor
		if json.Unmarshal(data, &saved) == nil && saved.DeviceID == state.DeviceID && !saved.NextHour.IsZero() {
			cursor = saved
			cursorLoaded = true
		}
	}
	pending, err := walkTelemetryOutbox(ctx, filepath.Join(c.dataDir, telemetryOutboxFile), nil, nil)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// If the cursor was never persisted, recover the older pending hour rather
	// than silently skipping it after a long outage or process restart.
	if err == nil && pending.DeviceID == state.DeviceID && !cursorLoaded {
		cursor.NextHour = pending.Hour
	}
	// Process at most a day per wake-up. The durable cursor retains older
	// unsent hours, so extended outages do not create a huge burst.
	for count := 0; count < 24 && cursor.NextHour.Before(end); count++ {
		if err := c.uploadHour(ctx, config, state, cursor.NextHour); err != nil {
			return err
		}
		cursor.NextHour = cursor.NextHour.Add(time.Hour)
		if err := writePrivateJSON(filepath.Join(c.dataDir, cursorFile), cursor); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(c.dataDir, telemetryOutboxFile)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) collectHour(ctx context.Context, hour time.Time, emit func(telemetryBatch) error) error {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start, until := hour.Unix(), hour.Add(time.Hour).Unix()
	params := map[string]interface{}{":start": start, ":until": until}
	var totals []struct {
		Allowed       int64 `sqlite:"allowed"`
		Blocked       int64 `sqlite:"blocked"`
		DNS           int64 `sqlite:"dns"`
		BytesSent     int64 `sqlite:"bytes_sent"`
		BytesReceived int64 `sqlite:"bytes_received"`
	}
	err := c.store.Execute(queryCtx, `SELECT
		COALESCE(SUM(CASE WHEN verdict IN (2,5,6,8) THEN 1 ELSE 0 END),0) AS allowed,
		COALESCE(SUM(CASE WHEN verdict IN (3,4) THEN 1 ELSE 0 END),0) AS blocked,
		COALESCE(SUM(CASE WHEN type = 'dns' THEN 1 ELSE 0 END),0) AS dns,
		COALESCE(SUM(bytes_sent),0) AS bytes_sent,
		COALESCE(SUM(bytes_received),0) AS bytes_received
		FROM history.connections WHERE strftime('%s', started)+0 >= :start AND strftime('%s', started)+0 < :until AND internal = 0`,
		orm.WithNamedArgs(params), orm.WithResult(&totals))
	if err != nil {
		return fmt.Errorf("query hourly totals: %w", err)
	}
	summary := hourlySummary{Hour: hour.Format(time.RFC3339)}
	if len(totals) > 0 {
		summary.Allowed, summary.Blocked, summary.DNS = totals[0].Allowed, totals[0].Blocked, totals[0].DNS
		summary.BytesSent, summary.BytesReceived = totals[0].BytesSent, totals[0].BytesReceived
	}
	for page := 0; ; page++ {
		var rows []struct {
			App     string `sqlite:"app"`
			Host    string `sqlite:"host"`
			Allowed int64  `sqlite:"allowed"`
			Blocked int64  `sqlite:"blocked"`
		}
		err = c.store.Execute(queryCtx, `SELECT COALESCE(NULLIF(profile_name,''),'Unknown') AS app,
			COALESCE(NULLIF(domain,''),NULLIF(remote_ip,''),'Unknown') AS host,
			SUM(CASE WHEN verdict IN (2,5,6,8) THEN 1 ELSE 0 END) AS allowed,
			SUM(CASE WHEN verdict IN (3,4) THEN 1 ELSE 0 END) AS blocked
			FROM history.connections WHERE strftime('%s', started)+0 >= :start AND strftime('%s', started)+0 < :until AND internal = 0
			GROUP BY app, host ORDER BY app, host LIMIT 1000 OFFSET :offset`,
			orm.WithNamedArgs(map[string]interface{}{":start": start, ":until": until, ":offset": page * 1000}),
			orm.WithResult(&rows))
		if err != nil {
			return fmt.Errorf("query daily destinations: %w", err)
		}
		batch := telemetryBatch{BatchID: fmt.Sprintf("h2/%s/%d", hour.Format("20060102T15"), page),
			DestinationMode: "hourly_delta",
			Hourly:          []hourlySummary{}, Destinations: make([]dailyDestination, 0, len(rows))}
		if page == 0 {
			batch.Hourly = append(batch.Hourly, summary)
		}
		for _, row := range rows {
			batch.Destinations = append(batch.Destinations, dailyDestination{
				Day: hour.Format("2006-01-02"), App: boundedLabel(row.App), Host: boundedLabel(row.Host),
				Allowed: row.Allowed, Blocked: row.Blocked,
			})
		}
		if err := emit(batch); err != nil {
			return err
		}
		if len(rows) < 1000 {
			break
		}
	}
	return nil
}

func (c *Client) postTelemetry(ctx context.Context, config Config, state State, batch telemetryBatch) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.ServerURL+"/api/v1/device/telemetry/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+state.Credential)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("telemetry rejected with HTTP %d", resp.StatusCode)
	}
	return nil
}
