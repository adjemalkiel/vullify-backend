package worker

import (
	"encoding/json"

	"github.com/google/uuid"
)

// RegistryCredentials holds registry auth to pass to the scanner subprocess.
type RegistryCredentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// ScanJob is queued on Redis (JSON) and processed by workers.
type ScanJob struct {
	ScanID    uuid.UUID            `json:"scan_id"`
	ImageRef  string               `json:"image_ref"`
	RegCreds  *RegistryCredentials `json:"reg_creds,omitempty"`
}

func encodeJob(j ScanJob) ([]byte, error) {
	return json.Marshal(j)
}

func decodeJob(data []byte) (ScanJob, error) {
	var j ScanJob
	err := json.Unmarshal(data, &j)
	return j, err
}
