-- Team Rockstars — per-member dismissal of transient Home alerts.
--
-- Run once against an existing database:
--   npx wrangler d1 execute team-rockstars --file=./migrations/006_alert_dismissals.sql --remote
--
-- Opportunity review alerts ("Thank you for finding this opportunity…") are
-- derived from the opportunity itself, so there is no notification row to mark.
-- This table records only that ONE member cleared ONE alert. The opportunity
-- and its review record are never touched, and no other member is affected.
--
-- kind    'opp_review' today; further transient alert types can reuse the table.
-- ref_id  the opportunity id (or the id of whatever the alert is derived from).
--
-- Alerts also expire on their own 24 hours after the review decision, which is
-- computed from opportunities.reviewed_at — no stored expiry is needed.

CREATE TABLE IF NOT EXISTS alert_dismissals (
  member_id    INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  kind         TEXT    NOT NULL,
  ref_id       INTEGER NOT NULL,
  dismissed_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (member_id, kind, ref_id)
);
