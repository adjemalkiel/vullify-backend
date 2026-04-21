package enrichment

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/google/uuid"
)

// scanCompletedPayload matches worker scan event JSON.
type scanCompletedPayload struct {
	Event  string `json:"event"`
	ScanID string `json:"scan_id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Start subscribes to Redis Pub/Sub and runs EnrichScan for successful scans.
func (e *Enricher) Start(ctx context.Context) error {
	if e.Redis == nil {
		return errors.New("enrichment: redis client required")
	}
	log := e.Log
	if log == nil {
		log = slog.Default()
	}

	chName := e.eventsChannel()
	pubsub := e.Redis.Subscribe(ctx, chName)
	defer func() { _ = pubsub.Close() }()

	log.Info("enrichment listener started", "channel", chName)

	msgCh := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			log.Info("enrichment listener stopped")
			return nil
		case msg, ok := <-msgCh:
			if !ok {
				return nil
			}
			if msg == nil {
				continue
			}
			payload := strings.TrimSpace(msg.Payload)
			if payload == "" {
				continue
			}
			var ev scanCompletedPayload
			if err := json.Unmarshal([]byte(payload), &ev); err != nil {
				log.Warn("enrichment: bad event json", "err", err)
				continue
			}
			if !strings.EqualFold(ev.Event, "scan.completed") {
				continue
			}
			if !strings.EqualFold(ev.Status, "completed") {
				continue
			}
			scanID, err := uuid.Parse(strings.TrimSpace(ev.ScanID))
			if err != nil {
				log.Warn("enrichment: bad scan_id", "scan_id", ev.ScanID, "err", err)
				continue
			}
			if err := e.EnrichScan(ctx, scanID); err != nil {
				log.Error("enrichment: enrich scan failed", "scan_id", scanID, "err", err)
			}
		}
	}
}
