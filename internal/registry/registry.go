package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Registry connector type names (match DB enum registry_type).
const (
	TypeDockerHub = "dockerhub"
	TypeGitLab    = "gitlab"
	TypeECR       = "ecr"
	TypeGCR       = "gcr"
	TypeGHCR      = "ghcr"
)

// RegistryConnector talks to a container registry (list repos/tags, resolve digests).
type RegistryConnector interface {
	TestConnection(ctx context.Context) error
	ListRepositories(ctx context.Context) ([]string, error)
	ListTags(ctx context.Context, repository string) ([]string, error)
	GetDigest(ctx context.Context, repository, tag string) (string, error)
}

// ErrUnsupportedType is returned when registryType is unknown.
var ErrUnsupportedType = errors.New("unsupported registry type")

// NewConnector builds a RegistryConnector from a type name and JSON credentials.
func NewConnector(registryType string, credentials json.RawMessage) (RegistryConnector, error) {
	switch strings.ToLower(strings.TrimSpace(registryType)) {
	case TypeDockerHub:
		var c DockerHubCredentials
		if err := json.Unmarshal(credentials, &c); err != nil {
			return nil, fmt.Errorf("dockerhub credentials: %w", err)
		}
		return NewDockerHub(c), nil
	case TypeGitLab:
		var c GitLabCredentials
		if err := json.Unmarshal(credentials, &c); err != nil {
			return nil, fmt.Errorf("gitlab credentials: %w", err)
		}
		return NewGitLab(c), nil
	case TypeECR:
		var c ECRCredentials
		if err := json.Unmarshal(credentials, &c); err != nil {
			return nil, fmt.Errorf("ecr credentials: %w", err)
		}
		return NewECR(c), nil
	case TypeGCR:
		c, err := parseGCRCredentialsBlob(credentials)
		if err != nil {
			return nil, fmt.Errorf("gcr credentials: %w", err)
		}
		return NewGCR(c)
	case TypeGHCR:
		var c GHCRCredentials
		if err := json.Unmarshal(credentials, &c); err != nil {
			return nil, fmt.Errorf("ghcr credentials: %w", err)
		}
		return NewGHCR(c), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedType, registryType)
	}
}
