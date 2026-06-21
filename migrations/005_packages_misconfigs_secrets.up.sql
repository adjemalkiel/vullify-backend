BEGIN;

CREATE TABLE packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT '',
    layer_digest TEXT NOT NULL DEFAULT '',
    licenses TEXT[],
    file_path TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_packages_scan_id ON packages(scan_id);

CREATE TABLE misconfigurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    type TEXT NOT NULL DEFAULT '',
    check_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    severity severity NOT NULL DEFAULT 'unknown',
    resolution TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL DEFAULT '',
    start_line INTEGER NOT NULL DEFAULT 0,
    end_line INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_misconfigurations_scan_id ON misconfigurations(scan_id);

CREATE TABLE secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    severity severity NOT NULL DEFAULT 'unknown',
    title TEXT NOT NULL DEFAULT '',
    match_text TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL DEFAULT '',
    start_line INTEGER NOT NULL DEFAULT 0,
    end_line INTEGER NOT NULL DEFAULT 0,
    layer_digest TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_secrets_scan_id ON secrets(scan_id);

COMMIT;
