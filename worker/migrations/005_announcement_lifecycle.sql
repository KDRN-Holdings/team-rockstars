-- Team Rockstars — announcement expiry / dismissal and nudge states.
--
-- Run once against an existing database:
--   npx wrangler d1 execute team-rockstars --file=./migrations/005_announcement_lifecycle.sql --remote
--
-- Purely additive. Three independent concepts are now modelled separately:
--   * viewed    — announcement_reads.read_at   (clears the unread badge)
--   * dismissed — announcement_reads.dismissed_at (hides it from ONE member's Home)
--   * expired   — announcements.expires_at     (hides it from everyone)
--
-- announcements.published_at records when an item actually went live, so the
-- 30-day default expiry is measured from publication rather than authoring.
-- Existing rows keep NULL and are treated as "published_at = approved_at or
-- created_at, expires 30 days later" by the app.
--
-- Nudges gain viewed_at and dismissed_at so a member can clear a reminder
-- without the nudge event disappearing from the admin history.
--
-- SQLite has no "ADD COLUMN IF NOT EXISTS"; re-running reports
-- "duplicate column name", which is safe to ignore.

ALTER TABLE announcements ADD COLUMN published_at TEXT;
ALTER TABLE announcements ADD COLUMN expires_at   TEXT;

ALTER TABLE announcement_reads ADD COLUMN dismissed_at TEXT;

ALTER TABLE nudges ADD COLUMN viewed_at    TEXT;
ALTER TABLE nudges ADD COLUMN dismissed_at TEXT;

-- Backfill publication time for everything already live, so existing
-- announcements get a sensible expiry window instead of vanishing.
UPDATE announcements
   SET published_at = COALESCE(approved_at, created_at)
 WHERE published_at IS NULL AND status = 'published';

CREATE INDEX IF NOT EXISTS idx_ann_expiry ON announcements(status, expires_at);
