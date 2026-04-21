package testutil

import (
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// migrateUp runs golang-migrate "up" from migrationsDir (no import of vullify/internal/db to avoid cycles).
func migrateUp(dsn, migrationsDir string) error {
	abs, err := filepath.Abs(migrationsDir)
	if err != nil {
		return fmt.Errorf("migrations path: %w", err)
	}
	p := filepath.ToSlash(abs)
	var src string
	if runtime.GOOS == "windows" {
		// golang-migrate file source expects file://C:/path (not file:///C:/... from url.URL on some versions).
		src = "file://" + p
	} else {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		src = (&url.URL{Scheme: "file", Path: p}).String()
	}

	m, err := migrate.New(src, dsn)
	if err != nil {
		return fmt.Errorf("migrate new: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}
