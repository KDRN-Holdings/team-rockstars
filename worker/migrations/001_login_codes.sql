-- Team Rockstars — add passwordless email login codes.
--
-- Run once against an existing database:
--   npx wrangler d1 execute team-rockstars --file=./migrations/001_login_codes.sql --remote
--
-- Additive only: no existing table or column is altered or dropped, so member
-- records, sessions, businesses, and opportunities are untouched.

CREATE TABLE IF NOT EXISTS login_codes (
  code_hash  TEXT    PRIMARY KEY,
  member_id  INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  expires_at TEXT    NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  used_at    TEXT,
  created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_code_member ON login_codes(member_id, used_at);
CREATE INDEX IF NOT EXISTS idx_code_expiry ON login_codes(expires_at);
