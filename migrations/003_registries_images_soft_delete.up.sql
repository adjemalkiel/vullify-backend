ALTER TABLE registries ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE images ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_registries_deleted_at ON registries (deleted_at);
CREATE INDEX IF NOT EXISTS idx_images_deleted_at ON images (deleted_at);
