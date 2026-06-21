package scanqueue

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// DefaultKey is the Redis list name for LPUSH/BRPOP scan jobs (must match worker).
const DefaultKey = "vullify:scan:queue"

// RegistryCredentials holds registry auth for the scanner subprocess.
// NOTE: Keep JSON shape in sync with worker.RegistryCredentials.
type RegistryCredentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// CredentialsFromRegistryJSON extracts scanner-compatible credentials from a
// JSON blob stored in the registries.credentials column.
// typ is the registry type (e.g. "ghcr", "dockerhub", "generic_v2").
func CredentialsFromRegistryJSON(typ string, raw json.RawMessage) *RegistryCredentials {
	if len(raw) == 0 {
		return nil
	}
	var creds map[string]string
	if err := json.Unmarshal(raw, &creds); err != nil {
		return nil
	}
	switch typ {
	case "ghcr":
		token := creds["github_token"]
		if token == "" {
			return nil
		}
		return &RegistryCredentials{
			Username: "pat",
			Password: token,
		}
	case "dockerhub", "generic_v2":
		u := creds["username"]
		p := creds["password"]
		if u == "" || p == "" {
			return nil
		}
		return &RegistryCredentials{
			Username: u,
			Password: p,
		}
	}
	return nil
}

// Enqueue pushes a worker-compatible job (LPUSH for BRPOP consumer).
func Enqueue(ctx context.Context, rdb *redis.Client, queueKey string, scanID uuid.UUID, imageRef string, regCreds *RegistryCredentials) error {
	if queueKey == "" {
		queueKey = DefaultKey
	}
	job := struct {
		ScanID   uuid.UUID            `json:"scan_id"`
		ImageRef string               `json:"image_ref"`
		RegCreds *RegistryCredentials `json:"reg_creds,omitempty"`
	}{
		ScanID:   scanID,
		ImageRef: imageRef,
		RegCreds: regCreds,
	}
	payload, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return rdb.LPush(ctx, queueKey, payload).Err()
}
