package webhook

import (
	"context"

	"vullify/internal/db"
)

type registryCtxKey struct{}

// matchedRegistryKey is set by auth middleware after signature/token validation.
var matchedRegistryKey = registryCtxKey{}

func withRegistry(ctx context.Context, reg db.RegistryRow) context.Context {
	return context.WithValue(ctx, matchedRegistryKey, reg)
}

func registryFromContext(ctx context.Context) (db.RegistryRow, bool) {
	v, ok := ctx.Value(matchedRegistryKey).(db.RegistryRow)
	return v, ok
}
