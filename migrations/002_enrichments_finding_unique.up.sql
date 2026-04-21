-- One enrichment row per finding for upserts.
CREATE UNIQUE INDEX IF NOT EXISTS enrichments_finding_id_key ON enrichments (finding_id);
