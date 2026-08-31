-- Team Rockstars — record WHY a member cannot comment on an opportunity.
--
-- Run once against an existing database:
--   npx wrangler d1 execute team-rockstars --file=./migrations/002_unable_reason.sql --remote
--
-- Adds the 'unable' status and an unable_reason column to
-- member_opportunity_status. SQLite cannot widen a CHECK constraint in place,
-- so the table is rebuilt and every existing row is copied across unchanged.
-- The legacy statuses (not_member, join_pending, banned) stay valid.
-- Safe to re-run: it copies whatever the live table currently holds.

DROP TABLE IF EXISTS member_opportunity_status_new;

CREATE TABLE member_opportunity_status_new (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  opportunity_id    INTEGER NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
  member_id         INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  status            TEXT    NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open','completed','not_member','join_pending','banned','unable')),
  unable_reason     TEXT,
  eligible_from     TEXT    NOT NULL DEFAULT (datetime('now')),
  completed_at      TEXT,
  status_changed_at TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (opportunity_id, member_id)
);

INSERT INTO member_opportunity_status_new
  (id, opportunity_id, member_id, status, unable_reason, eligible_from, completed_at, status_changed_at)
SELECT id, opportunity_id, member_id, status, NULL, eligible_from, completed_at, status_changed_at
FROM member_opportunity_status;

DROP TABLE member_opportunity_status;
ALTER TABLE member_opportunity_status_new RENAME TO member_opportunity_status;

CREATE INDEX IF NOT EXISTS idx_mos_member ON member_opportunity_status(member_id, status);
CREATE INDEX IF NOT EXISTS idx_mos_completed ON member_opportunity_status(completed_at);
