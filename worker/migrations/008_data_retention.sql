-- Team Rockstars — data retention support.
--
-- Run once against an existing database:
--   npx wrangler d1 execute team-rockstars --file=./migrations/008_data_retention.sql --remote
--
-- Purely additive. Nothing here deletes data; it only adds the columns, the
-- indexes and the two record-keeping tables the nightly retention job needs.
--
-- Why each piece exists
--   opportunities.completed_at  when a post stopped needing tags, which is what
--                               the 12-month archive clock runs from. archived_at
--                               already exists and keeps its meaning.
--   nudge_stats                 aggregate nudge counts per month, written BEFORE
--                               old dismissed nudge rows are deleted, so admin
--                               reporting survives the cleanup.
--   retention_runs              one row per nightly run with the counts, so a
--                               failed or surprising cleanup can be diagnosed.
--                               No member data, no message text.
--
-- monthly_participation already exists and is the historical ranking snapshot.
-- The job fills it for every closed month before anything is purged, so
-- deleting an old opportunity can never change a past month's standings.
--
-- SQLite has no "ADD COLUMN IF NOT EXISTS"; re-running reports
-- "duplicate column name", which is safe to ignore.

ALTER TABLE opportunities ADD COLUMN completed_at TEXT;

-- Retention scans are date-range deletes; these keep them off full-table scans.
CREATE INDEX IF NOT EXISTS idx_opp_archived      ON opportunities(archived_at);
CREATE INDEX IF NOT EXISTS idx_opp_completed     ON opportunities(completed_at);
CREATE INDEX IF NOT EXISTS idx_annreads_dismiss  ON announcement_reads(dismissed_at);
CREATE INDEX IF NOT EXISTS idx_nudges_dismiss    ON nudges(dismissed_at);
CREATE INDEX IF NOT EXISTS idx_alertdis_at       ON alert_dismissals(dismissed_at);
CREATE INDEX IF NOT EXISTS idx_mos_opp           ON member_opportunity_status(opportunity_id, status);

-- Aggregate nudge history. Survives deletion of the individual nudge rows.
CREATE TABLE IF NOT EXISTS nudge_stats (
  month_key    TEXT    NOT NULL,               -- 'YYYY-MM' of the nudge date
  recipient_id INTEGER NOT NULL,               -- kept even if the member leaves
  sent         INTEGER NOT NULL DEFAULT 0,
  viewed       INTEGER NOT NULL DEFAULT 0,
  dismissed    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (month_key, recipient_id)
);

-- Observability for the nightly job. Counts only — never message content.
CREATE TABLE IF NOT EXISTS retention_runs (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ran_at   TEXT NOT NULL DEFAULT (datetime('now')),
  summary  TEXT NOT NULL,                      -- JSON: {"loginCodes":12,...}
  ok       INTEGER NOT NULL DEFAULT 1,
  note     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_retention_ran ON retention_runs(ran_at);
