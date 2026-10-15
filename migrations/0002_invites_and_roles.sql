-- Dhark Library: convites, perfis e controle exclusivo da administração
PRAGMA foreign_keys = ON;
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin'));
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked'));
CREATE TABLE IF NOT EXISTS invites (
 id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, code_hint TEXT NOT NULL,
 max_uses INTEGER NOT NULL CHECK(max_uses>=1), used_count INTEGER NOT NULL DEFAULT 0 CHECK(used_count>=0),
 created_by TEXT NOT NULL REFERENCES users(id), created_at INTEGER NOT NULL, expires_at INTEGER, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_invites_created ON invites(created_at);
CREATE TABLE IF NOT EXISTS user_profiles (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 learning_goal TEXT NOT NULL, level TEXT NOT NULL CHECK(level IN ('basico','intermediario','curso_completo'))
);
