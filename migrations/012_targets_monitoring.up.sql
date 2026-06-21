-- 012_targets_monitoring.up.sql
CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_id UUID NOT NULL REFERENCES images(id),
    scan_frequency TEXT NOT NULL DEFAULT '24h',
    latest_scan_id UUID REFERENCES scans(id),
    latest_scan_status TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_targets_image_id ON targets(image_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_targets_latest_scan ON targets(latest_scan_id);
