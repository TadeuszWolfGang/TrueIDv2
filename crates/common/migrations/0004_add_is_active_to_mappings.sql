ALTER TABLE mappings ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;
CREATE INDEX idx_mappings_is_active ON mappings (is_active);
