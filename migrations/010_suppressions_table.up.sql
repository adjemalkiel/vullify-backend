CREATE TABLE suppressions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(50),
    pkg_name VARCHAR(255),
    image_id UUID REFERENCES images(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    accepted_by TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
