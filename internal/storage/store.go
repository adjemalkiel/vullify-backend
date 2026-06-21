package storage

import (
	"context"
	"os"
	"sync"
)

// ObjectStore provides a simple key-value interface for offloading
// binary objects (e.g. SBOMs) to an external store.
type ObjectStore interface {
	Put(ctx context.Context, key string, data []byte, contentType string) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// New returns an ObjectStore implementation chosen at startup.
// When STORAGE_ENDPOINT is set it returns a MinIO-backed store;
// otherwise it returns a no-op implementation that never errors.
func New() ObjectStore {
	if os.Getenv("STORAGE_ENDPOINT") != "" {
		return newMinIOStore()
	}
	return &noopStore{}
}

// noopStore discards all puts and returns nil for all gets.
type noopStore struct{}

func (n *noopStore) Put(_ context.Context, _ string, _ []byte, _ string) error {
	return nil
}

func (n *noopStore) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}

var (
	noopStoreInst *noopStore
	noopStoreOnce sync.Once
)

// Noop returns a shared no-op store singleton.
func Noop() ObjectStore {
	noopStoreOnce.Do(func() { noopStoreInst = &noopStore{} })
	return noopStoreInst
}
