-- Team Rockstars — Cloudflare D1 schema
-- Apply with (run from the worker/ folder):
--   npx wrangler d1 execute team-rockstars --file=./schema.sql --remote
--
-- Safe to re-run: every statement is IF NOT EXISTS / INSERT OR IGNORE.
--
-- Clean beta state: no demo members, businesses, opportunities, announcements,
-- comments, or leaderboard activity. Only the initial administrator is seeded
-- (at the bottom of this file), with NO password — they set one via the real
-- password-reset email.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- identity ---

CREATE TABLE IF NOT EXISTS members (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  email               TEXT    NOT NULL UNIQUE,
  full_name           TEXT    NOT NULL DEFAULT '',
  business_owner_name TEXT    NOT NULL DEFAULT '',
  avatar              TEXT,                       -- data URL, resized client-side
  password_hash       TEXT,                       -- NULL until the member sets one
  password_salt       TEXT,
  password_iterations INTEGER,
  role                TEXT    NOT NULL DEFAULT 'member' CHECK (role IN ('member','admin')),
  status              TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  tag_group           TEXT    NOT NULL DEFAULT 'active' CHECK (tag_group IN ('active','paused')),
  joined_at           TEXT    NOT NULL DEFAULT (datetime('now')),
  last_login_at       TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT    PRIMARY KEY,             -- SHA-256 of the cookie value
  member_id   INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  expires_at  TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  user_agent  TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_member ON sessions(member_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS reset_tokens (
  token_hash TEXT    PRIMARY KEY,              -- SHA-256 of the emailed token
  member_id  INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  expires_at TEXT    NOT NULL,
  used_at    TEXT,                             -- non-NULL => single-use spent
  created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_reset_member ON reset_tokens(member_id);

-- Rate limiting for forgot-password so the endpoint cannot be used to spam.
CREATE TABLE IF NOT EXISTS reset_requests (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT NOT NULL,
  ip         TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_reset_req ON reset_requests(email, created_at);

-- -------------------------------------------------------------- businesses ---
-- A member may run several businesses; exactly one is primary.
-- Tag preferences are business-specific, never member-specific.

CREATE TABLE IF NOT EXISTS businesses (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id   INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  name        TEXT    NOT NULL,
  industry    TEXT    NOT NULL DEFAULT '',
  website     TEXT    NOT NULL DEFAULT '',
  city          TEXT  NOT NULL DEFAULT '',      -- primary location
  radius        TEXT  NOT NULL DEFAULT 'none',  -- none|5|10|25|50|100|statewide|nationwide|virtual|custom
  service_state TEXT  NOT NULL DEFAULT '',      -- US state, only when radius='statewide'
  is_primary  INTEGER NOT NULL DEFAULT 0,
  active      INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_biz_member ON businesses(member_id, active);

-- One row per preference entry, so keywords stay queryable.
CREATE TABLE IF NOT EXISTS business_preferences (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  business_id INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
  kind        TEXT    NOT NULL CHECK (kind IN ('want','not_want','preferred_area','avoid_area')),
  value       TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pref_biz ON business_preferences(business_id, kind);

-- ----------------------------------------------------------- opportunities ---

CREATE TABLE IF NOT EXISTS opportunities (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  beneficiary_id        INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  business_id           INTEGER REFERENCES businesses(id) ON DELETE SET NULL,
  business_display_name TEXT    NOT NULL,        -- snapshot at submit time
  submitted_by_id       INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  facebook_url          TEXT    NOT NULL,
  facebook_group_name   TEXT    NOT NULL DEFAULT '',
  location              TEXT    NOT NULL DEFAULT '',
  status                TEXT    NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active','pending_review','declined')),
  review_note           TEXT    NOT NULL DEFAULT '',   -- private, owner-only
  reviewed_by_id        INTEGER REFERENCES members(id) ON DELETE SET NULL,
  reviewed_at           TEXT,
  decline_reason        TEXT    NOT NULL DEFAULT '',
  created_at            TEXT    NOT NULL DEFAULT (datetime('now')),
  archived_at           TEXT
);
CREATE INDEX IF NOT EXISTS idx_opp_status ON opportunities(status, archived_at);
CREATE INDEX IF NOT EXISTS idx_opp_benef ON opportunities(beneficiary_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_opp_url ON opportunities(facebook_url)
  WHERE archived_at IS NULL;

-- Per-member tagging state. Fanned out at submit time so "missed" is computable.
CREATE TABLE IF NOT EXISTS member_opportunity_status (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  opportunity_id    INTEGER NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
  member_id         INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  status            TEXT    NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open','completed','not_member','join_pending','banned')),
  eligible_from     TEXT    NOT NULL DEFAULT (datetime('now')),
  completed_at      TEXT,
  status_changed_at TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (opportunity_id, member_id)
);
CREATE INDEX IF NOT EXISTS idx_mos_member ON member_opportunity_status(member_id, status);
CREATE INDEX IF NOT EXISTS idx_mos_completed ON member_opportunity_status(completed_at);

-- ------------------------------------------------------- saved comments -----
-- Private to the authoring member; never readable by anyone else.

CREATE TABLE IF NOT EXISTS saved_comments (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id           INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  business_member_id  INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  label               TEXT    NOT NULL DEFAULT '',
  text                TEXT    NOT NULL,
  created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at          TEXT
);
CREATE INDEX IF NOT EXISTS idx_comment_member ON saved_comments(member_id);

-- ------------------------------------------------------- announcements ------

CREATE TABLE IF NOT EXISTS announcements (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id        INTEGER REFERENCES members(id) ON DELETE SET NULL,
  submitted_by_id  INTEGER REFERENCES members(id) ON DELETE SET NULL,
  title            TEXT    NOT NULL,
  message          TEXT    NOT NULL,
  status           TEXT    NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','published','declined')),
  pinned           INTEGER NOT NULL DEFAULT 0,
  approved_by_id   INTEGER REFERENCES members(id) ON DELETE SET NULL,
  approved_at      TEXT,
  decline_reason   TEXT    NOT NULL DEFAULT '',
  created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_ann_status ON announcements(status, pinned, created_at);

CREATE TABLE IF NOT EXISTS announcement_reads (
  announcement_id INTEGER NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
  member_id       INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  read_at         TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (announcement_id, member_id)
);

-- ---------------------------------------------------------- leadership ------
-- Chapter titles, deliberately separate from the admin role.

CREATE TABLE IF NOT EXISTS leadership (
  role_key    TEXT    PRIMARY KEY
                CHECK (role_key IN ('president','vicePresident','chapterTech','ambassador')),
  member_id   INTEGER REFERENCES members(id) ON DELETE SET NULL,
  assigned_by INTEGER REFERENCES members(id) ON DELETE SET NULL,
  assigned_at TEXT
);
INSERT OR IGNORE INTO leadership (role_key, member_id) VALUES
  ('president', NULL), ('vicePresident', NULL),
  ('chapterTech', NULL), ('ambassador', NULL);

-- Audit trail for administrator handovers.
CREATE TABLE IF NOT EXISTS role_transfers (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  from_member_id INTEGER REFERENCES members(id) ON DELETE SET NULL,
  to_member_id   INTEGER REFERENCES members(id) ON DELETE SET NULL,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ------------------------------------------------------- facebook groups ----

CREATE TABLE IF NOT EXISTS fb_groups (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT    NOT NULL,
  url         TEXT    NOT NULL DEFAULT '',
  category    TEXT    NOT NULL DEFAULT '',
  city        TEXT    NOT NULL DEFAULT '',
  county      TEXT    NOT NULL DEFAULT '',
  state       TEXT    NOT NULL DEFAULT '',
  nationwide  INTEGER NOT NULL DEFAULT 0,
  featured    INTEGER NOT NULL DEFAULT 0,
  sort_order  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_groups_featured ON fb_groups(featured, sort_order);
CREATE INDEX IF NOT EXISTS idx_groups_geo ON fb_groups(state, county, city);

CREATE TABLE IF NOT EXISTS group_membership (
  group_id   INTEGER NOT NULL REFERENCES fb_groups(id) ON DELETE CASCADE,
  member_id  INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  status     TEXT    NOT NULL DEFAULT 'unknown'
               CHECK (status IN ('joined','not_joined','requested','unknown')),
  updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (group_id, member_id)
);

-- ------------------------------------------------------------- nudges -------

CREATE TABLE IF NOT EXISTS nudges (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id    INTEGER REFERENCES members(id) ON DELETE SET NULL,
  recipient_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  message      TEXT    NOT NULL DEFAULT '',
  read_at      TEXT,
  created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_nudge_recipient ON nudges(recipient_id, created_at);

-- ------------------------------------------------ monthly participation -----
-- Rankings are derived from member_opportunity_status for the live month.
-- Closed months are snapshotted here so history never shifts.

CREATE TABLE IF NOT EXISTS monthly_participation (
  month_key       TEXT    NOT NULL,             -- 'YYYY-MM'
  member_id       INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  tags_completed  INTEGER NOT NULL DEFAULT 0,
  posts_found     INTEGER NOT NULL DEFAULT 0,
  eligible        INTEGER NOT NULL DEFAULT 0,
  missed          INTEGER NOT NULL DEFAULT 0,
  rank            INTEGER,
  goal            INTEGER NOT NULL DEFAULT 25,
  closed_at       TEXT,
  PRIMARY KEY (month_key, member_id)
);

-- Chapter-wide settings, so the tag goal is not baked into the front end.
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('monthly_tag_goal', '25'),
  ('missed_grace_hours', '72'),
  ('inactive_threshold_days', '7');

-- ------------------------------------------------------- initial admin -----
-- No password hash: the first login happens through the real reset email.
INSERT OR IGNORE INTO members (email, full_name, role, status)
VALUES ('admin@sculpt-rx.net', 'Chapter Administrator', 'admin', 'active');
