package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CompactSummaryStore captures locally and freezes bounded deliveries before
// any network request. Acknowledgment must match the immutable queued delivery.
type CompactSummaryStore interface {
	ConfigureCompactSummaries(context.Context, string, bool) (bool, error)
	NextCompactSummary(context.Context, string) (*CompactDelivery, error)
	AcknowledgeCompactSummary(context.Context, string, string, int64) error
}

type CompactDelivery struct {
	StreamID string
	Sequence int64
	Body     []byte
}

type CompactHour struct {
	Hour          string `json:"hour" sqlite:"hour"`
	Allowed       int64  `json:"allowed" sqlite:"allowed"`
	Blocked       int64  `json:"blocked" sqlite:"blocked"`
	DNS           int64  `json:"dns" sqlite:"dns"`
	BytesSent     int64  `json:"bytes_sent" sqlite:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received" sqlite:"bytes_received"`
}

type CompactDestination struct {
	Country       string `json:"country" sqlite:"country"`
	Day           string `json:"day" sqlite:"day"`
	ProfileID     string `json:"profile_id" sqlite:"profile_id"`
	App           string `json:"app" sqlite:"app"`
	Host          string `json:"host" sqlite:"host"`
	Allowed       int64  `json:"allowed" sqlite:"allowed"`
	Blocked       int64  `json:"blocked" sqlite:"blocked"`
	BytesSent     int64  `json:"bytes_sent" sqlite:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received" sqlite:"bytes_received"`
}

type CompactCategory struct {
	Day       string   `json:"day"`
	ProfileID string   `json:"profile_id"`
	Host      string   `json:"host"`
	Country   string   `json:"country"`
	Lists     []string `json:"lists"`
	Blocked   int64    `json:"blocked"`
}

type CompactBatch struct {
	StreamID     string               `json:"stream_id"`
	Sequence     int64                `json:"sequence"`
	StartedAt    string               `json:"started_at"`
	Hourly       []CompactHour        `json:"hourly"`
	Destinations []CompactDestination `json:"destinations"`
	Categories   []CompactCategory    `json:"categories"`
}

// MarshalCompactBatch bounds labels before freezing the delivery. Stable profile
// identities remain independent from human-readable names.
func MarshalCompactBatch(batch CompactBatch) ([]byte, error) {
	if len(batch.Hourly) > 24 || len(batch.Destinations) > 200 || len(batch.Categories) > 200 || batch.Sequence < 1 {
		return nil, errors.New("invalid compact batch size or sequence")
	}
	clean := func(value string) string {
		return boundedLabel(strings.Map(func(r rune) rune {
			if r < 32 || r == 127 {
				return '\uFFFD'
			}
			return r
		}, value))
	}
	for i := range batch.Destinations {
		row := &batch.Destinations[i]
		if !localApplicationID.MatchString(row.ProfileID) {
			row.ProfileID = ""
		}

		row.App, row.Host = clean(row.App), clean(row.Host)
		if len(row.Country) != 2 || row.Country[0] < 'A' || row.Country[0] > 'Z' || row.Country[1] < 'A' || row.Country[1] > 'Z' {
			row.Country = ""
		}
	}
	if batch.Categories == nil {
		batch.Categories = []CompactCategory{}
	}
	for i := range batch.Categories {
		row := &batch.Categories[i]
		if !localApplicationID.MatchString(row.ProfileID) {
			row.ProfileID = ""
		}
		row.Host = clean(row.Host)
		if len(row.Country) != 2 || row.Country[0] < 'A' || row.Country[0] > 'Z' || row.Country[1] < 'A' || row.Country[1] > 'Z' {
			row.Country = ""
		}
		if row.Lists == nil {
			row.Lists = []string{}
		}
		if len(row.Lists) > 64 {
			return nil, errors.New("too many block lists")
		}
	}
	return json.Marshal(batch)
}

func (c *Client) activateCompactCapture(ctx context.Context) error {
	store, ok := c.store.(CompactSummaryStore)
	if !ok {
		return nil
	}
	state, err := readIdentity(c.dataDir)
	if err != nil {
		return err
	}
	if state.DeviceID == "" || state.Credential == "" {
		return errors.New("device is not enrolled")
	}
	ready, err := store.ConfigureCompactSummaries(ctx, state.DeviceID, c.compactSummaryEnabled.Load())
	if err == nil {
		c.compactSummaryActive.Store(ready)
	}
	return err
}

func (c *Client) flushCompactSummaries(ctx context.Context, config Config, state State, store CompactSummaryStore) error {
	// An already frozen legacy hour predates compact capture. Deliver it before
	// the server switches this enrollment to the new protocol; never rescan old
	// raw history during the transition.
	path := filepath.Join(c.dataDir, telemetryOutboxFile)
	pending, err := walkTelemetryOutbox(ctx, path, nil, nil)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && pending.DeviceID == state.DeviceID {
		if err := c.uploadHour(ctx, config, state, pending.Hour); err != nil {
			return err
		}
		if err := writePrivateJSON(filepath.Join(c.dataDir, cursorFile), telemetryCursor{DeviceID: state.DeviceID, NextHour: pending.Hour.Add(time.Hour)}); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	for page := 0; page < 24; page++ {
		delivery, err := store.NextCompactSummary(ctx, state.DeviceID)
		if err != nil {
			return err
		}
		if delivery == nil {
			return nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.ServerURL+"/api/v1/device/summaries/", bytes.NewReader(delivery.Body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+state.Credential)
		response, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		var ack struct {
			Accepted bool   `json:"accepted"`
			StreamID string `json:"stream_id"`
			Sequence int64  `json:"sequence"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&ack)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusAccepted {
			return fmt.Errorf("compact summary rejected with HTTP %d", response.StatusCode)
		}
		if decodeErr != nil || !ack.Accepted || ack.StreamID != delivery.StreamID || ack.Sequence != delivery.Sequence {
			return errors.New("compact summary acknowledgment does not match delivery")
		}
		if err := store.AcknowledgeCompactSummary(ctx, state.DeviceID, delivery.StreamID, delivery.Sequence); err != nil {
			return err
		}
	}
	return nil
}
