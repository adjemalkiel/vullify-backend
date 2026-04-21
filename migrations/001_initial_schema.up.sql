-- Vullify core schema: registries, images, scans, findings, enrichments, SBOMs, webhooks.

CREATE TYPE registry_type AS ENUM ('dockerhub', 'gitlab', 'ecr', 'gcr');
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed');
CREATE TYPE scan_trigger AS ENUM ('manual', 'schedule', 'webhook');
CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'unknown');
CREATE TYPE sbom_format AS ENUM ('cyclonedx', 'spdx');

CREATE TABLE registries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    "type" registry_type NOT NULL,
    url TEXT NOT NULL,
    credentials JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    registry_id UUID NOT NULL REFERENCES registries (id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    digest TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_images_registry_id ON images (registry_id);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_id UUID NOT NULL REFERENCES images (id) ON DELETE CASCADE,
    status scan_status NOT NULL DEFAULT 'pending',
    triggered_by scan_trigger NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    trivy_version TEXT
);

CREATE INDEX idx_scans_image_id_status ON scans (image_id, status);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    vulnerability_id VARCHAR(255) NOT NULL,
    package_name TEXT NOT NULL,
    installed_version TEXT,
    fixed_version TEXT,
    severity severity NOT NULL,
    title TEXT,
    description TEXT,
    data_source TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_scan_id_severity ON findings (scan_id, severity);

CREATE TABLE enrichments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    epss_score DOUBLE PRECISION,
    epss_percentile DOUBLE PRECISION,
    kev_listed BOOLEAN NOT NULL DEFAULT false,
    kev_date_added DATE,
    known_exploits JSONB,
    enriched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scan_sboms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    "format" sbom_format NOT NULL,
    content JSONB NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source VARCHAR(255) NOT NULL,
    event_type VARCHAR(255) NOT NULL,
    payload JSONB NOT NULL,
    processed BOOLEAN NOT NULL DEFAULT false,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
