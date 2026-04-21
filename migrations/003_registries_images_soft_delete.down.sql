DROP INDEX IF EXISTS idx_images_deleted_at;
DROP INDEX IF EXISTS idx_registries_deleted_at;

ALTER TABLE images DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE registries DROP COLUMN IF EXISTS deleted_at;
