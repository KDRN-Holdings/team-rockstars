-- Team Rockstars — opportunities can come from Facebook or Nextdoor.
--
-- Run once against an existing database:
--   npx wrangler d1 execute team-rockstars --file=./migrations/007_platform.sql --remote
--
-- Additive and safe for existing data. Every row written before Nextdoor
-- support is backfilled to 'facebook', which is also what the app assumes for
-- any row where the value is NULL, so historical opportunities keep working
-- with no manual updates.
--
-- The link itself still lives in facebook_url. The column keeps its name to
-- avoid a rename across every query; platform says which site it points at.
--
-- SQLite has no "ADD COLUMN IF NOT EXISTS"; re-running reports
-- "duplicate column name", which is safe to ignore.

ALTER TABLE opportunities ADD COLUMN platform TEXT NOT NULL DEFAULT 'facebook';

UPDATE opportunities SET platform = 'facebook' WHERE platform IS NULL OR platform = '';
