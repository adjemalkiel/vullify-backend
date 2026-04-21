package worker

import (
	"encoding/json"

	"github.com/google/uuid"
)

// ScanJob is queued on Redis (JSON) and processed by workers.
type ScanJob struct {
	ScanID   uuid.UUID `json:"scan_id"`
	ImageRef string    `json:"image_ref"`
}

func encodeJob(j ScanJob) ([]byte, error) {
	return json.Marshal(j)
}

func decodeJob(data []byte) (ScanJob, error) {
	var j ScanJob
	err := json.Unmarshal(data, &j)
	return j, err
}
