-- Execute esta migration no D1 antes de implantar o Worker atualizado.
CREATE TABLE IF NOT EXISTS temporary_admins (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 created_by TEXT NOT NULL REFERENCES users(id),
 created_at INTEGER NOT NULL DEFAULT (unixepoch()),
 expires_at INTEGER NOT NULL,
 revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_temporary_admins_expires ON temporary_admins(expires_at);
