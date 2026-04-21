package db

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

// Migrate runs all pending "up" migrations from migrationsDir using golang-migrate.
// migrationsDir should be a path to the directory containing *.up.sql files (e.g. "./migrations").
func Migrate(dsn string, migrationsDir string) error {
	src, err := migrateFileURL(migrationsDir)
	if err != nil {
		return err
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

func migrateFileURL(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("migrations path: %w", err)
	}
	p := filepath.ToSlash(abs)
	if runtime.GOOS == "windows" {
		return "file://" + p, nil
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	return u.String(), nil
}
