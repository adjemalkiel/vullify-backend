package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vullify/internal/scanner"
)

// PersistScanResults persists all scan data (findings, packages, misconfigs, secrets, SBOMs)
// and marks the scan as completed in one transaction.
func PersistScanResults(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, res *scanner.ScanResult, trivyVersion string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM findings WHERE scan_id = $1`, scanID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM scan_sboms WHERE scan_id = $1`, scanID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM packages WHERE scan_id = $1`, scanID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM misconfigurations WHERE scan_id = $1`, scanID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM secrets WHERE scan_id = $1`, scanID); err != nil {
		return err
	}

	counts := computeSeverityCounts(res.Vulnerabilities)

	rows := vulnResultsToFindingRows(res.Vulnerabilities)
	if len(rows) > 0 {
		batch := &pgx.Batch{}
		for _, r := range rows {
			sev := normalizeSeverity(r.Severity)
			batch.Queue(`
				INSERT INTO findings (
					scan_id, vulnerability_id, package_name, installed_version, fixed_version,
					severity, title, description, data_source,
					cvss_v3_score, cvss_v3_vector, primary_url, layer_digest, layer_index
				) VALUES (
					$1, $2, $3, $4, $5,
					$6::severity, $7, $8, $9,
					$10, $11, $12, $13, $14
				)`,
				scanID, r.VulnerabilityID, r.PackageName, nullIfEmpty(r.InstalledVersion), nullIfEmpty(r.FixedVersion),
				sev, nullIfEmpty(r.Title), nullIfEmpty(r.Description), nullIfEmpty(r.DataSource),
				nullIfZero(r.CVSSV3Score), nullIfEmpty(r.CVSSV3Vector), nullIfEmpty(r.PrimaryURL), nullIfEmpty(r.LayerDigest), nullIfZero(r.LayerIndex),
			)
		}
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return fmt.Errorf("finding row %d: %w", i, err)
			}
		}
		if err := br.Close(); err != nil {
			return err
		}
	}

	if len(res.Packages) > 0 {
		batch := &pgx.Batch{}
		for _, p := range res.Packages {
			batch.Queue(`
				INSERT INTO packages (scan_id, name, version, type, layer_digest, licenses, file_path)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				scanID, p.Name, p.Version, p.Type, nullIfEmpty(p.LayerDigest), p.Licenses, p.FilePath,
			)
		}
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return fmt.Errorf("package row %d: %w", i, err)
			}
		}
		if err := br.Close(); err != nil {
			return err
		}
	}

	if len(res.Misconfigurations) > 0 {
		batch := &pgx.Batch{}
		for _, m := range res.Misconfigurations {
			sev := normalizeSeverity(m.Severity)
			batch.Queue(`
				INSERT INTO misconfigurations (scan_id, type, check_id, title, description, severity, resolution, file_path, start_line, end_line)
				VALUES ($1, $2, $3, $4, $5, $6::severity, $7, $8, $9, $10)`,
				scanID, m.Type, m.CheckID, m.Title, m.Description, sev, nullIfEmpty(m.Resolution), m.FilePath, m.StartLine, m.EndLine,
			)
		}
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return fmt.Errorf("misconfiguration row %d: %w", i, err)
			}
		}
		if err := br.Close(); err != nil {
			return err
		}
	}

	if len(res.Secrets) > 0 {
		batch := &pgx.Batch{}
		for _, s := range res.Secrets {
			sev := normalizeSeverity(s.Severity)
			batch.Queue(`
				INSERT INTO secrets (scan_id, rule_id, category, severity, title, match_text, file_path, start_line, end_line, layer_digest)
				VALUES ($1, $2, $3, $4::severity, $5, $6, $7, $8, $9, $10)`,
				scanID, s.RuleID, s.Category, sev, nullIfEmpty(s.Title), s.MatchText, s.FilePath, s.StartLine, s.EndLine, nullIfEmpty(s.LayerDigest),
			)
		}
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return fmt.Errorf("secret row %d: %w", i, err)
			}
		}
		if err := br.Close(); err != nil {
			return err
		}
	}

	if len(res.SBOMCycloneDX) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO scan_sboms (scan_id, "format", content, generated_at)
			VALUES ($1, 'cyclonedx'::sbom_format, $2::jsonb, now())
		`, scanID, res.SBOMCycloneDX); err != nil {
			return err
		}
	}

	if len(res.SBOMSPDX) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO scan_sboms (scan_id, "format", content, generated_at)
			VALUES ($1, 'spdx'::sbom_format, $2::jsonb, now())
		`, scanID, res.SBOMSPDX); err != nil {
			return err
		}
	}

	var imageOS, imageArch string
	var imageSize *int64
	var layerCount *int
	if res.Metadata != nil {
		imageOS = res.Metadata.OS
		imageArch = res.Metadata.Architecture
		if res.Metadata.ImageSize > 0 {
			imageSize = &res.Metadata.ImageSize
		}
		if res.Metadata.LayerCount > 0 {
			layerCount = &res.Metadata.LayerCount
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE scans
		SET status = 'completed',
		    completed_at = now(),
		    error_message = NULL,
		    trivy_version = NULLIF($2, ''),
		    critical_count = $3,
		    high_count = $4,
		    medium_count = $5,
		    low_count = $6,
		    unknown_count = $7,
		    image_os = NULLIF($8, ''),
		    image_arch = NULLIF($9, ''),
		    image_size = $10,
		    layer_count = $11
		WHERE id = $1
	`,
		scanID, trivyVersion,
		counts.critical, counts.high, counts.medium, counts.low, counts.unknown,
		imageOS, imageArch, imageSize, layerCount,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

type severityCounts struct {
	critical, high, medium, low, unknown int
}

func computeSeverityCounts(vulns []scanner.VulnResult) severityCounts {
	var c severityCounts
	for _, v := range vulns {
		switch normalizeSeverity(v.Severity) {
		case "critical":
			c.critical++
		case "high":
			c.high++
		case "medium":
			c.medium++
		case "low":
			c.low++
		default:
			c.unknown++
		}
	}
	return c
}

func vulnResultsToFindingRows(vs []scanner.VulnResult) []FindingRow {
	out := make([]FindingRow, 0, len(vs))
	for _, v := range vs {
		vid := v.VulnerabilityID
		if vid == "" {
			vid = "UNKNOWN"
		}
		pkg := v.PackageName
		if pkg == "" {
			pkg = "unknown"
		}
		out = append(out, FindingRow{
			VulnerabilityID:  vid,
			PackageName:      pkg,
			InstalledVersion: v.InstalledVersion,
			FixedVersion:     v.FixedVersion,
			Severity:         v.Severity,
			Title:            v.Title,
			Description:      v.Description,
			DataSource:       v.DataSource,
			CVSSV3Score:      v.CVSSV3Score,
			CVSSV3Vector:     v.CVSSV3Vector,
			PrimaryURL:       v.PrimaryURL,
			LayerDigest:      v.LayerDigest,
			LayerIndex:       v.LayerIndex,
		})
	}
	return out
}
