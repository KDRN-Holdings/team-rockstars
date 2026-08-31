-- Team Rockstars — public "what are they looking for?" summary on an opportunity.
--
-- Run once against an existing database:
--   npx wrangler d1 execute team-rockstars --file=./migrations/003_opportunity_summary.sql --remote
--
-- Purely additive: one new column with a default, so every existing row stays
-- valid and no data is rewritten. This is the PUBLIC request description shown
-- to the whole team — distinct from review_note (private, owner-only) and
-- decline_reason.
--
-- SQLite has no "ADD COLUMN IF NOT EXISTS"; re-running this reports
-- "duplicate column name: opportunity_summary", which is safe to ignore.

ALTER TABLE opportunities ADD COLUMN opportunity_summary TEXT NOT NULL DEFAULT '';
