-- Team Rockstars — services within a business.
--
-- Run once against an existing database:
--   npx wrangler d1 execute team-rockstars --file=./migrations/004_business_services.sql --remote
--
-- Structure: member -> businesses -> services. Purely additive:
--   * a new business_services table
--   * opportunities gain service_id (relationship) and service_name (display
--     snapshot, so history reads correctly even if a service is renamed)
--   * saved_comments gain service_id, NULL meaning a general business comment
--
-- No existing row is rewritten. Opportunities and comments created before this
-- migration keep service_id NULL and are treated as "General".
--
-- SQLite has no "ADD COLUMN IF NOT EXISTS"; re-running reports
-- "duplicate column name", which is safe to ignore.

CREATE TABLE IF NOT EXISTS business_services (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  business_id INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
  name        TEXT    NOT NULL,
  description TEXT    NOT NULL DEFAULT '',
  active      INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_svc_biz ON business_services(business_id, active);

ALTER TABLE opportunities ADD COLUMN service_id INTEGER;
ALTER TABLE opportunities ADD COLUMN service_name TEXT NOT NULL DEFAULT '';
ALTER TABLE saved_comments ADD COLUMN service_id INTEGER;
