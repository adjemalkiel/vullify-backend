package scheduler

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"vullify/internal/db"
	"vullify/internal/imageref"
	"vullify/internal/registry"
	"vullify/internal/scanqueue"
)

func jobTimeoutFor(interval time.Duration) time.Duration {
	const minTO = 30 * time.Minute
	const maxTO = 2 * time.Hour
	if interval <= 0 {
		return minTO
	}
	if interval < minTO {
		return minTO
	}
	if interval > maxTO {
		return maxTO
	}
	return interval
}

func runRegistrySync(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	regs, err := db.ListActiveRegistries(ctx, pool)
	if err != nil {
		log.Error("registry sync: list registries", "err", err)
		return
	}
	for _, reg := range regs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := registry.NewConnector(reg.Type, reg.Credentials)
		if err != nil {
			log.Warn("registry sync: connector", "registry_id", reg.ID, "err", err)
			continue
		}
		repos, err := conn.ListRepositories(ctx)
		if err != nil {
			log.Warn("registry sync: list repositories", "registry_id", reg.ID, "err", err)
			continue
		}
		for _, repo := range repos {
			select {
			case <-ctx.Done():
				return
			default:
			}
			tags, err := conn.ListTags(ctx, repo)
			if err != nil {
				log.Warn("registry sync: list tags", "registry_id", reg.ID, "repository", repo, "err", err)
				continue
			}
			for _, tag := range tags {
				if _, err := db.UpsertImage(ctx, pool, reg.ID, repo, tag); err != nil {
					log.Warn("registry sync: upsert image", "registry_id", reg.ID, "repository", repo, "tag", tag, "err", err)
				}
			}
			if err := db.SoftDeleteImageTagsNotIn(ctx, pool, reg.ID, repo, tags); err != nil {
				log.Warn("registry sync: soft-delete stale tags", "registry_id", reg.ID, "repository", repo, "err", err)
			}
		}
		if err := db.SoftDeleteImagesForRepositoriesNotIn(ctx, pool, reg.ID, repos); err != nil {
			log.Warn("registry sync: soft-delete stale repositories", "registry_id", reg.ID, "err", err)
		}
	}
}

func runPeriodicRescan(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, cfg Config, log *slog.Logger) {
	cutoff := time.Now().Add(-cfg.StaleScanAge)
	ids, err := db.ListImageIDsStaleForRescan(ctx, pool, cutoff)
	if err != nil {
		log.Error("periodic rescan: list images", "err", err)
		return
	}
	qk := queueKey(cfg)
	for _, imageID := range ids {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := enqueueScheduledScan(ctx, pool, rdb, qk, imageID, log); err != nil {
			log.Warn("periodic rescan: enqueue", "image_id", imageID, "err", err)
		}
	}
}

func runChangeDetection(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, cfg Config, log *slog.Logger) {
	rows, err := db.ListImagesForChangeDetection(ctx, pool)
	if err != nil {
		log.Error("change detection: list images", "err", err)
		return
	}
	qk := queueKey(cfg)
	for _, row := range rows {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := registry.NewConnector(row.RegistryType, row.Credentials)
		if err != nil {
			log.Warn("change detection: connector", "image_id", row.ID, "err", err)
			continue
		}
		remote, err := conn.GetDigest(ctx, row.Repository, row.Tag)
		if err != nil {
			log.Warn("change detection: get digest", "image_id", row.ID, "err", err)
			continue
		}
		remoteNorm := normalizeDigest(remote)
		if row.Digest != nil && normalizeDigest(*row.Digest) == remoteNorm {
			continue
		}
		if err := enqueueScheduledScan(ctx, pool, rdb, qk, row.ID, log); err != nil {
			log.Warn("change detection: enqueue", "image_id", row.ID, "err", err)
			continue
		}
		if err := db.UpdateImageDigest(ctx, pool, row.ID, remote); err != nil {
			log.Warn("change detection: update digest", "image_id", row.ID, "err", err)
		}
	}
}

func enqueueScheduledScan(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, qk string, imageID uuid.UUID, log *slog.Logger) error {
	busy, err := db.ImageHasPendingOrRunningScan(ctx, pool, imageID)
	if err != nil {
		return err
	}
	if busy {
		return nil
	}
	detail, err := db.GetImageByID(ctx, pool, imageID)
	if err != nil {
		return err
	}
	regRow, err := db.GetRegistryByID(ctx, pool, detail.RegistryID)
	if err != nil {
		return err
	}
	scanID, err := db.InsertScheduledScan(ctx, pool, imageID)
	if err != nil {
		return err
	}
	ref := imageref.BuildImagePullRef(detail.RegistryURL, detail.Repository, detail.Tag)
	if err := scanqueue.Enqueue(ctx, rdb, qk, scanID, ref, scanqueue.CredentialsFromRegistryJSON(regRow.Type, regRow.Credentials)); err != nil {
		return err
	}
	log.Info("scheduled scan enqueued", "scan_id", scanID, "image_id", imageID)
	return nil
}

func normalizeDigest(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
