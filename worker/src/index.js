/**
 * Team Rockstars API — Cloudflare Worker
 *
 * Design note: /api/bootstrap returns one object shaped like the front end's
 * existing client state (members, businesses, opportunities, statuses,
 * comments, announcements, leadership, groups, nudges, settings). That lets the
 * UI keep its current structure — swap the localStorage read for one fetch —
 * instead of rewriting every screen. Mutations are individual POSTs that return
 * the affected rows; the client refetches bootstrap after writes.
 *
 * Security invariants:
 *  - Passwords: PBKDF2-HMAC-SHA256, per-user random salt, verified server-side.
 *  - Sessions: opaque 32-byte token in an HttpOnly cookie; only its SHA-256 is
 *    stored, so a database leak cannot be replayed as a login.
 *  - Reset tokens: 32 bytes, SHA-256 stored, 60-minute expiry, single use.
 *  - Every /api/admin/* route re-reads the caller's role from D1. Hiding a
 *    button in the UI is never the control.
 */

// 100,000 is the maximum Cloudflare Workers' WebCrypto accepts for PBKDF2.
const PBKDF2_ITERATIONS = 100_000;
const SESSION_DAYS = 30;
const RESET_TTL_MIN = 60;
const RESET_MAX_PER_HOUR = 4;
const OTP_TTL_MIN = 10;          // login code lifetime
const OTP_MAX_ATTEMPTS = 5;      // wrong guesses before the code is burned
const OTP_MAX_PER_HOUR = 5;      // code requests per address per hour
const NUDGE_COOLDOWN_MS = 24 * 60 * 60 * 1000;

/* ------------------------------------------------------------------ crypto -- */

const enc = new TextEncoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

function randomBytes(n = 32) {
  return crypto.getRandomValues(new Uint8Array(n));
}
function b64url(bytes) {
  return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function sha256(text) {
  return b64(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}
async function pbkdf2(password, saltBytes, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations }, key, 256
  );
  return b64(bits);
}
async function hashPassword(password) {
  const salt = randomBytes(16);
  return {
    hash: await pbkdf2(password, salt, PBKDF2_ITERATIONS),
    salt: b64(salt),
    iterations: PBKDF2_ITERATIONS
  };
}
/** Constant-time string compare — avoids leaking hash bytes via response time. */
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function verifyPassword(password, member) {
  if (!member.password_hash || !member.password_salt) return false;
  // Always the count stored WITH this account's hash — never a fixed value.
  const stored = member.password_iterations || PBKDF2_ITERATIONS;
  let candidate;
  try {
    candidate = await pbkdf2(password, unb64(member.password_salt), stored);
  } catch (e) {
    // A hash written above the platform ceiling can never be re-derived here.
    // Fail as a normal password mismatch rather than a 500, so the member can
    // recover with "Forgot password" and be re-hashed at a supported count.
    return false;
  }
  return timingSafeEqual(candidate, member.password_hash);
}

/* ------------------------------------------------------------------- http --- */

function corsHeaders(env, request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (env.APP_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  const ok = allowed.includes(origin) ? origin : allowed[0] || '';
  return {
    'Access-Control-Allow-Origin': ok,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin'
  };
}
function json(data, init = {}, env, request) {
  return new Response(JSON.stringify(data), {
    status: init.status || 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...corsHeaders(env, request),
      ...(init.headers || {})
    }
  });
}
const ok = (env, request, data = {}) => json({ ok: true, ...data }, {}, env, request);
const fail = (env, request, status, error) => json({ ok: false, error }, { status }, env, request);

function sessionCookie(token, env, maxAgeSec) {
  // The app and API share the registrable domain sculpt-rx.net, so requests
  // between them are same-site and SameSite=Lax is sent normally — including on
  // iOS Safari, which blocks cross-site cookies outright.
  //
  // No Domain attribute is set unless COOKIE_DOMAIN is provided: a host-only
  // cookie for the API subdomain is narrower and still travels on every fetch
  // to that host.
  const parts = [
    `tr_session=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    `SameSite=${env.COOKIE_SAMESITE || 'None'}`,
    `Max-Age=${maxAgeSec}`
  ];
  if (env.COOKIE_DOMAIN) parts.push(`Domain=${env.COOKIE_DOMAIN}`);
  return parts.join('; ');
}
function readCookie(request, name) {
  const raw = request.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}
async function readJson(request) {
  try { return await request.json(); } catch { return {}; }
}
const clean = v => (typeof v === 'string' ? v.trim() : '');
const isEmail = v => /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v || '');

/* ---------------------------------------------------------------- session --- */

/**
 * Reads the presented session token. The Authorization header is the primary
 * transport: Pages and the Worker are different registrable domains, so the
 * session cookie is third-party and iOS Safari refuses to send it. The cookie
 * is still accepted so sessions created before this change keep working.
 */
function readSessionToken(request) {
  const auth = request.headers.get('Authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  if (m) return m[1].trim();
  return readCookie(request, 'tr_session');
}

async function currentMember(request, env) {
  const raw = readSessionToken(request);
  if (!raw) return null;
  const row = await env.DB.prepare(
    `SELECT m.* FROM sessions s
       JOIN members m ON m.id = s.member_id
      WHERE s.token = ?1 AND s.expires_at > datetime('now')`
  ).bind(await sha256(raw)).first();
  if (!row || row.status !== 'active') return null;
  return row;
}
async function createSession(memberId, request, env) {
  const raw = b64url(randomBytes(32));
  const expires = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString().slice(0, 19).replace('T', ' ');
  await env.DB.prepare(
    `INSERT INTO sessions (token, member_id, expires_at, user_agent) VALUES (?1, ?2, ?3, ?4)`
  ).bind(await sha256(raw), memberId, expires, (request.headers.get('User-Agent') || '').slice(0, 200)).run();
  return raw;
}
async function requireMember(request, env) {
  const me = await currentMember(request, env);
  if (!me) throw { status: 401, error: 'Not signed in' };
  return me;
}
/** Admin gate. Re-reads role from D1 on every call. */
async function requireAdmin(request, env) {
  const me = await requireMember(request, env);
  if (me.role !== 'admin') throw { status: 403, error: 'Administrator access required' };
  return me;
}

/* -------------------------------------------------------------- login otp --- */

/**
 * Six digits from rejection-sampled random bytes, so every code is equally
 * likely. Returned in plaintext only to be emailed; only its hash is stored.
 */
function generateOtp() {
  const max = Math.floor(0xffffffff / 1000000) * 1000000;
  for (;;) {
    const v = new DataView(randomBytes(4).buffer).getUint32(0, false);
    if (v < max) return String(v % 1000000).padStart(6, '0');
  }
}

async function sendLoginCodeEmail(env, toEmail, code) {
  const html = `<!doctype html><html><body style="margin:0;background:#faf9f7;font-family:-apple-system,'Helvetica Neue',Helvetica,Arial,sans-serif;color:#1c1d1f">
  <div style="max-width:480px;margin:0 auto;padding:32px 24px">
    <div style="font-size:13px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#9a9c9f;margin-bottom:6px">Team Rockstars</div>
    <h1 style="margin:0 0 12px;font-size:22px;font-weight:700;letter-spacing:-0.02em">Your login code</h1>
    <p style="margin:0 0 20px;font-size:15px;line-height:1.5;color:#4a4c4f">Enter this code in Team Rockstars to sign in.</p>
    <div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:34px;font-weight:700;letter-spacing:0.16em;padding:16px 20px;background:#fff;border:1px solid #e6e5e2;border-radius:14px;display:inline-block">${code}</div>
    <p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#6b6d70">This code expires in ${OTP_TTL_MIN} minutes and can be used once. If you did not request it, you can ignore this email &mdash; nobody can sign in without the code.</p>
  </div></body></html>`;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: env.MAIL_FROM,
      to: toEmail,
      subject: `Team Rockstars login code: ${code}`,
      html,
      text: `Your Team Rockstars login code is ${code}\n\nIt expires in ${OTP_TTL_MIN} minutes and can be used once.`
    })
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${(await res.text()).slice(0, 300)}`);
}

/** Issues a code, invalidating any earlier unused ones for that member. */
async function issueLoginCode(env, member) {
  const code = generateOtp();
  const expires = new Date(Date.now() + OTP_TTL_MIN * 60000).toISOString().slice(0, 19).replace('T', ' ');
  await env.DB.batch([
    // A newly requested code supersedes anything outstanding.
    env.DB.prepare(`DELETE FROM login_codes WHERE member_id = ?1 AND used_at IS NULL`).bind(member.id),
    env.DB.prepare(
      `INSERT INTO login_codes (code_hash, member_id, expires_at) VALUES (?1, ?2, ?3)`
    ).bind(await sha256(code), member.id, expires)
  ]);
  await sendLoginCodeEmail(env, member.email, code);
}

/* ------------------------------------------------------------------ email --- */

async function sendResetEmail(env, toEmail, token, isNew) {
  const url = `${(env.APP_ORIGIN || '').split(',')[0].trim()}/?reset=${encodeURIComponent(token)}`;
  const heading = isNew ? 'Create your Team Rockstars password' : 'Reset your Team Rockstars password';
  const lead = isNew
    ? 'An administrator added you to Team Rockstars. Use the button below to create your password.'
    : 'Use the button below to choose a new password for your Team Rockstars account.';

  const html = `<!doctype html><html><body style="margin:0;background:#faf9f7;font-family:-apple-system,'Helvetica Neue',Helvetica,Arial,sans-serif;color:#1c1d1f">
  <div style="max-width:480px;margin:0 auto;padding:32px 24px">
    <div style="font-size:13px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#9a9c9f;margin-bottom:6px">Team Rockstars</div>
    <h1 style="margin:0 0 12px;font-size:22px;font-weight:700;letter-spacing:-0.02em">${heading}</h1>
    <p style="margin:0 0 20px;font-size:15px;line-height:1.5;color:#4a4c4f">${lead}</p>
    <a href="${url}" style="display:inline-block;padding:14px 22px;border-radius:12px;background:#3d4fb8;color:#fff;font-size:15px;font-weight:600;text-decoration:none">${isNew ? 'Create password' : 'Reset password'}</a>
    <p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#6b6d70">This link expires in ${RESET_TTL_MIN} minutes and can be used once. If you did not request it, you can ignore this email.</p>
    <p style="margin:14px 0 0;font-size:12px;color:#9a9c9f;word-break:break-all">${url}</p>
  </div></body></html>`;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: env.MAIL_FROM,
      to: [toEmail],
      subject: heading,
      html,
      text: `${heading}\n\n${lead}\n\n${url}\n\nThis link expires in ${RESET_TTL_MIN} minutes and can be used once.`
    })
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${(await res.text()).slice(0, 300)}`);
}

async function issueReset(env, member, isNew) {
  const token = b64url(randomBytes(32));
  const expires = new Date(Date.now() + RESET_TTL_MIN * 60000).toISOString().slice(0, 19).replace('T', ' ');
  await env.DB.prepare(
    `INSERT INTO reset_tokens (token_hash, member_id, expires_at) VALUES (?1, ?2, ?3)`
  ).bind(await sha256(token), member.id, expires).run();
  await sendResetEmail(env, member.email, token, isNew);
}

/* -------------------------------------------------------------- bootstrap --- */

const memberPublic = m => ({
  id: m.id, email: m.email, fullName: m.full_name,
  businessOwnerName: m.business_owner_name, avatar: m.avatar,
  role: m.role, status: m.status, tagGroup: m.tag_group,
  joinedAt: m.joined_at, hasPassword: !!m.password_hash
});

async function bootstrap(me, env) {
  const q = sql => env.DB.prepare(sql);
  const [
    members, businesses, prefs, opportunities, statuses,
    comments, announcements, reads, leadership, groups,
    membership, nudges, transfers, settings, participation
  ] = await env.DB.batch([
    q(`SELECT * FROM members ORDER BY full_name`),
    q(`SELECT * FROM businesses WHERE active = 1`),
    q(`SELECT * FROM business_preferences`),
    q(`SELECT * FROM opportunities ORDER BY created_at DESC`),
    q(`SELECT * FROM member_opportunity_status`),
    q(`SELECT * FROM saved_comments WHERE member_id = ?1`).bind(me.id),
    q(`SELECT * FROM announcements ORDER BY pinned DESC, created_at DESC LIMIT 200`),
    q(`SELECT * FROM announcement_reads WHERE member_id = ?1`).bind(me.id),
    q(`SELECT * FROM leadership`),
    q(`SELECT * FROM fb_groups ORDER BY featured DESC, sort_order, name`),
    q(`SELECT * FROM group_membership WHERE member_id = ?1`).bind(me.id),
    // Admins need the audit trail; members only ever see their own nudges.
    me.role === 'admin'
      ? q(`SELECT * FROM nudges ORDER BY created_at DESC LIMIT 200`)
      : q(`SELECT * FROM nudges WHERE recipient_id = ?1 ORDER BY created_at DESC LIMIT 50`).bind(me.id),
    q(`SELECT * FROM role_transfers ORDER BY created_at DESC LIMIT 10`),
    q(`SELECT * FROM settings`),
    q(`SELECT * FROM monthly_participation WHERE closed_at IS NOT NULL`)
  ]);

  // Queried outside the batch: databases without migrations/004 have no
  // business_services table, and the app must still load there.
  let services = { results: [] };
  try {
    services = await env.DB.prepare(`SELECT * FROM business_services WHERE active = 1 ORDER BY name`).all();
  } catch (e) { services = { results: [] }; }

  // Only this member's dismissed Home alerts — nobody needs anyone else's.
  let dismissals = { results: [] };
  try {
    dismissals = await env.DB.prepare(
      `SELECT kind, ref_id FROM alert_dismissals WHERE member_id = ?1 LIMIT 500`
    ).bind(me.id).all();
  } catch (e) { dismissals = { results: [] }; }

  const prefsByBiz = {};
  for (const p of prefs.results) {
    const bag = (prefsByBiz[p.business_id] = prefsByBiz[p.business_id] || {
      wants: [], notWants: [], preferred: [], avoid: []
    });
    if (p.kind === 'want') bag.wants.push(p.value);
    else if (p.kind === 'not_want') bag.notWants.push(p.value);
    else if (p.kind === 'preferred_area') bag.preferred.push(p.value);
    else bag.avoid.push(p.value);
  }

  const settingsMap = {};
  for (const s of settings.results) settingsMap[s.key] = s.value;

  const leadershipMap = {};
  for (const l of leadership.results) leadershipMap[l.role_key] = l.member_id;

  // Members see published announcements plus their own submissions.
  const visibleAnn = announcements.results.filter(
    a => a.status === 'published' || a.submitted_by_id === me.id || me.role === 'admin'
  );

  return {
    me: memberPublic(me),
    members: members.results.map(memberPublic),
    businesses: businesses.results.map(b => ({
      id: b.id, memberId: b.member_id, name: b.name, industry: b.industry,
      website: b.website, city: b.city, radius: b.radius,
      serviceState: b.service_state || '',
      primary: !!b.is_primary, active: !!b.active, createdAt: b.created_at,
      ...(prefsByBiz[b.id] || { wants: [], notWants: [], preferred: [], avoid: [] })
    })),
    opportunities: opportunities.results.map(o => ({
      id: o.id, beneficiaryId: o.beneficiary_id, businessId: o.business_id,
      businessDisplayName: o.business_display_name, submittedById: o.submitted_by_id,
      facebookUrl: o.facebook_url, facebookGroupName: o.facebook_group_name,
      // The stored value is returned as-is. Only a legacy row with no value at
      // all (column absent, NULL, or empty) falls back to Facebook.
      platform: (o.platform === null || o.platform === undefined || o.platform === '')
        ? 'facebook' : o.platform,
      location: o.location, status: o.status,
      serviceId: ('service_id' in o) ? o.service_id : null,
      serviceName: ('service_name' in o) ? (o.service_name || '') : '',
      // Public request summary ("what are they looking for?"). Empty on
      // databases that have not yet had migrations/003 applied.
      notes: ('opportunity_summary' in o) ? (o.opportunity_summary || '') : '',
      // The private review note is only for the owner and admins.
      reviewNote: (o.beneficiary_id === me.id || me.role === 'admin') ? o.review_note : '',
      reviewedById: o.reviewed_by_id, reviewedAt: o.reviewed_at,
      declineReason: o.decline_reason, createdAt: o.created_at, archivedAt: o.archived_at
    })),
    statuses: statuses.results.map(s => ({
      id: s.id, opportunityId: s.opportunity_id, memberId: s.member_id,
      status: s.status, eligibleFrom: s.eligible_from,
      reason: ('unable_reason' in s) ? (s.unable_reason || '') : '',
      completedAt: s.completed_at, statusChangedAt: s.status_changed_at
    })),
    comments: comments.results.map(c => ({
      id: c.id, memberId: c.member_id, businessMemberId: c.business_member_id,
      label: c.label, text: c.text,
      serviceId: ('service_id' in c) ? c.service_id : null,
      createdAt: c.created_at
    })),
    services: services.results.map(s2 => ({
      id: s2.id, businessId: s2.business_id, name: s2.name,
      description: s2.description || '', active: !!s2.active
    })),
    announcements: visibleAnn.map(a => ({
      id: a.id, authorId: a.author_id, submittedById: a.submitted_by_id,
      title: a.title, message: a.message, status: a.status, pinned: !!a.pinned,
      approvedById: a.approved_by_id, approvedAt: a.approved_at,
      declineReason: a.decline_reason, createdAt: a.created_at,
      // Present only once migrations/005 has run; the client falls back to
      // "published + 30 days" when they are missing.
      publishedAt: ('published_at' in a) ? (a.published_at || a.approved_at || a.created_at) : (a.approved_at || a.created_at),
      expiresAt: ('expires_at' in a) ? (a.expires_at || null) : null
    })),
    alertDismissals: dismissals.results.map(d => ({ memberId: me.id, kind: d.kind, refId: d.ref_id })),
    annReads: reads.results.map(r => ({
      announcementId: r.announcement_id, memberId: r.member_id, readAt: r.read_at,
      dismissedAt: ('dismissed_at' in r) ? (r.dismissed_at || null) : null
    })),
    leadership: leadershipMap,
    groups: groups.results.map(g => ({
      id: g.id, name: g.name, url: g.url, category: g.category,
      city: g.city, county: g.county, state: g.state,
      nationwide: !!g.nationwide, featured: !!g.featured, sortOrder: g.sort_order
    })),
    groupStatus: membership.results.map(m2 => ({ groupId: m2.group_id, status: m2.status })),
    nudges: nudges.results.map(n => ({
      id: n.id, senderId: n.sender_id, recipientId: n.recipient_id,
      message: n.message, readAt: n.read_at, createdAt: n.created_at,
      viewedAt: ('viewed_at' in n) ? (n.viewed_at || null) : null,
      dismissedAt: ('dismissed_at' in n) ? (n.dismissed_at || null) : null
    })),
    roleTransfers: transfers.results.map(t => ({
      id: t.id, fromMemberId: t.from_member_id, toMemberId: t.to_member_id, createdAt: t.created_at
    })),
    closedMonths: participation.results,
    settings: {
      monthlyTagGoal: +(settingsMap.monthly_tag_goal || 25),
      missedGraceHours: +(settingsMap.missed_grace_hours || 72),
      inactiveThresholdDays: +(settingsMap.inactive_threshold_days || 7)
    }
  };
}

/* ----------------------------------------------------------------- routes --- */

const routes = {
  /* ---- auth ---- */

  'POST /api/auth/login': async (request, env) => {
    const { email, password } = await readJson(request);
    const addr = clean(email).toLowerCase();
    if (!isEmail(addr) || !password) throw { status: 400, error: 'Enter your email and password.' };

    const member = await env.DB.prepare(`SELECT * FROM members WHERE lower(email) = ?1`).bind(addr).first();
    // One message for every failure mode, so login cannot enumerate accounts.
    const generic = { status: 401, error: 'That email and password do not match an account.' };
    if (!member) { await pbkdf2(password, randomBytes(16), PBKDF2_ITERATIONS); throw generic; }
    if (member.status !== 'active') throw { status: 403, error: 'This account is deactivated. Contact an administrator.' };
    if (!member.password_hash) throw { status: 403, error: 'No password set yet. Use “Forgot password” to create one.' };
    if (!(await verifyPassword(password, member))) throw generic;

    const token = await createSession(member.id, request, env);
    await env.DB.prepare(`UPDATE members SET last_login_at = datetime('now') WHERE id = ?1`).bind(member.id).run();
    // token is returned in the body because the cookie cannot cross sites.
    // The cookie is still set for same-site/desktop clients that accept it.
    return json({ ok: true, token, me: memberPublic(member) }, {
      headers: { 'Set-Cookie': sessionCookie(token, env, SESSION_DAYS * 86400) }
    }, env, request);
  },

  'POST /api/auth/logout': async (request, env) => {
    const raw = readSessionToken(request);
    if (raw) await env.DB.prepare(`DELETE FROM sessions WHERE token = ?1`).bind(await sha256(raw)).run();
    return json({ ok: true }, { headers: { 'Set-Cookie': sessionCookie('', env, 0) } }, env, request);
  },

  'GET /api/auth/me': async (request, env) => {
    const me = await currentMember(request, env);
    return me ? ok(env, request, { me: memberPublic(me) }) : fail(env, request, 401, 'Not signed in');
  },

  'POST /api/auth/request-code': async (request, env) => {
    const { email } = await readJson(request);
    const addr = clean(email).toLowerCase();
    if (!isEmail(addr)) throw { status: 400, error: 'Enter a valid email address.' };

    // Rate limit per address, reusing the existing request log table.
    const recent = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM reset_requests
        WHERE email = ?1 AND created_at > datetime('now','-1 hour')`
    ).bind(addr).first();
    if ((recent?.n || 0) >= OTP_MAX_PER_HOUR) {
      throw { status: 429, error: 'Too many login codes requested. Try again in an hour.' };
    }
    await env.DB.prepare(`INSERT INTO reset_requests (email, ip) VALUES (?1, ?2)`)
      .bind(addr, request.headers.get('CF-Connecting-IP') || '').run();

    const member = await env.DB.prepare(`SELECT * FROM members WHERE lower(email) = ?1`).bind(addr).first();
    if (member && member.status === 'active') {
      await issueLoginCode(env, member);
    }
    // Identical response either way, so the endpoint cannot enumerate accounts.
    return ok(env, request, { sent: true });
  },

  'POST /api/auth/verify-code': async (request, env) => {
    const { email, code } = await readJson(request);
    const addr = clean(email).toLowerCase();
    const digits = clean(code).replace(/\D/g, '');
    // One message for every failure, so a wrong code cannot reveal whether the
    // address exists or whether a code is outstanding.
    const generic = { status: 401, error: 'That code is not valid or has expired. Request a new one.' };
    if (!isEmail(addr) || digits.length !== 6) throw generic;

    const member = await env.DB.prepare(`SELECT * FROM members WHERE lower(email) = ?1`).bind(addr).first();
    if (!member || member.status !== 'active') throw generic;

    const row = await env.DB.prepare(
      `SELECT * FROM login_codes
        WHERE member_id = ?1 AND used_at IS NULL
        ORDER BY created_at DESC LIMIT 1`
    ).bind(member.id).first();
    if (!row) throw generic;

    if (new Date(row.expires_at.replace(' ', 'T') + 'Z') < new Date()) {
      await env.DB.prepare(`DELETE FROM login_codes WHERE code_hash = ?1`).bind(row.code_hash).run();
      throw generic;
    }
    if (row.attempts >= OTP_MAX_ATTEMPTS) {
      await env.DB.prepare(`DELETE FROM login_codes WHERE code_hash = ?1`).bind(row.code_hash).run();
      throw { status: 429, error: 'Too many incorrect attempts. Request a new login code.' };
    }

    const presented = await sha256(digits);
    if (!timingSafeEqual(presented, row.code_hash)) {
      await env.DB.prepare(`UPDATE login_codes SET attempts = attempts + 1 WHERE code_hash = ?1`)
        .bind(row.code_hash).run();
      throw generic;
    }

    // Correct: burn the code, then open a normal server-side session.
    await env.DB.prepare(`UPDATE login_codes SET used_at = datetime('now') WHERE code_hash = ?1`)
      .bind(row.code_hash).run();
    const token = await createSession(member.id, request, env);
    await env.DB.prepare(`UPDATE members SET last_login_at = datetime('now') WHERE id = ?1`)
      .bind(member.id).run();
    return json({ ok: true, token, me: memberPublic(member) }, {
      headers: { 'Set-Cookie': sessionCookie(token, env, SESSION_DAYS * 86400) }
    }, env, request);
  },

  'POST /api/auth/forgot': async (request, env) => {
    const { email } = await readJson(request);
    const addr = clean(email).toLowerCase();
    if (!isEmail(addr)) throw { status: 400, error: 'Enter a valid email address.' };

    const recent = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM reset_requests
        WHERE email = ?1 AND created_at > datetime('now','-1 hour')`
    ).bind(addr).first();
    if ((recent?.n || 0) >= RESET_MAX_PER_HOUR) throw { status: 429, error: 'Too many reset requests. Try again later.' };

    await env.DB.prepare(`INSERT INTO reset_requests (email, ip) VALUES (?1, ?2)`)
      .bind(addr, request.headers.get('CF-Connecting-IP') || '').run();

    const member = await env.DB.prepare(`SELECT * FROM members WHERE lower(email) = ?1`).bind(addr).first();
    if (member && member.status === 'active') {
      await issueReset(env, member, !member.password_hash);
    }
    // Same response either way — never reveals whether an address is registered.
    return ok(env, request, { sent: true });
  },

  'POST /api/auth/reset': async (request, env) => {
    const { token, password } = await readJson(request);
    if (!token) throw { status: 400, error: 'Missing reset token.' };
    if (!password || String(password).length < 10) {
      throw { status: 400, error: 'Choose a password of at least 10 characters.' };
    }
    const row = await env.DB.prepare(`SELECT * FROM reset_tokens WHERE token_hash = ?1`)
      .bind(await sha256(token)).first();
    if (!row) throw { status: 400, error: 'This reset link is not valid.' };
    if (row.used_at) throw { status: 400, error: 'This reset link has already been used.' };
    if (new Date(row.expires_at.replace(' ', 'T') + 'Z') < new Date()) {
      throw { status: 400, error: 'This reset link has expired. Request a new one.' };
    }
    const { hash, salt, iterations } = await hashPassword(String(password));
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE members SET password_hash = ?1, password_salt = ?2, password_iterations = ?3 WHERE id = ?4`
      ).bind(hash, salt, iterations, row.member_id),
      env.DB.prepare(`UPDATE reset_tokens SET used_at = datetime('now') WHERE token_hash = ?1`).bind(row.token_hash),
      // Any other outstanding link for this member dies with the reset.
      env.DB.prepare(`UPDATE reset_tokens SET used_at = datetime('now')
                       WHERE member_id = ?1 AND used_at IS NULL`).bind(row.member_id),
      // Existing sessions are revoked so a stolen session cannot outlive a reset.
      env.DB.prepare(`DELETE FROM sessions WHERE member_id = ?1`).bind(row.member_id)
    ]);
    return ok(env, request);
  },

  /* ---- shared data ---- */

  'GET /api/bootstrap': async (request, env) => {
    const me = await requireMember(request, env);
    return ok(env, request, { data: await bootstrap(me, env) });
  },

  'PATCH /api/profile': async (request, env) => {
    const me = await requireMember(request, env);
    const b = await readJson(request);
    await env.DB.prepare(
      // business_owner_name is still updatable by an admin flow, but the member
      // profile form no longer sends it.
      `UPDATE members SET full_name = COALESCE(?1, full_name),
                          business_owner_name = COALESCE(?2, business_owner_name),
                          avatar = ?3
        WHERE id = ?4`
    ).bind(clean(b.fullName) || null, clean(b.businessOwnerName) || null,
           b.avatar === undefined ? me.avatar : b.avatar, me.id).run();
    return ok(env, request);
  },

  /* ---- businesses ---- */

  'POST /api/businesses': async (request, env) => {
    const me = await requireMember(request, env);
    const b = await readJson(request);
    if (!clean(b.name)) throw { status: 400, error: 'Enter the business name.' };
    const existing = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM businesses WHERE member_id = ?1 AND active = 1`
    ).bind(me.id).first();
    const res = await env.DB.prepare(
      `INSERT INTO businesses (member_id, name, industry, website, city, radius, service_state, is_primary)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8)`
    ).bind(me.id, clean(b.name), clean(b.industry), clean(b.website), clean(b.city),
           clean(b.radius) || 'none',
           clean(b.radius) === 'statewide' ? clean(b.serviceState) : '',
           (existing?.n || 0) === 0 ? 1 : 0).run();
    await writePrefs(env, res.meta.last_row_id, b);
    await writeServices(env, res.meta.last_row_id, b.services);
    return ok(env, request, { id: res.meta.last_row_id });
  },

  'PATCH /api/businesses': async (request, env) => {
    const me = await requireMember(request, env);
    const b = await readJson(request);
    const owned = await ownBusiness(env, me, b.id);
    await env.DB.prepare(
      `UPDATE businesses SET name = ?1, industry = ?2, website = ?3, city = ?4,
                             radius = ?5, service_state = ?6, updated_at = datetime('now')
        WHERE id = ?7`
    ).bind(clean(b.name) || owned.name, clean(b.industry), clean(b.website),
           clean(b.city), clean(b.radius) || 'none',
           clean(b.radius) === 'statewide' ? clean(b.serviceState) : '',
           owned.id).run();
    await writePrefs(env, owned.id, b);
    await writeServices(env, owned.id, b.services);
    return ok(env, request);
  },

  /** Create or rename a service inside one of my businesses. */
  'POST /api/services': async (request, env) => {
    const me = await requireMember(request, env);
    const b = await readJson(request);
    const biz = await ownBusiness(env, me, b.businessId);
    const name = clean(b.name).slice(0, 80);
    if (!name) throw { status: 400, error: 'Give the service a name.' };
    try {
      if (b.id) {
        await env.DB.prepare(
          `UPDATE business_services SET name = ?1, description = ?2
            WHERE id = ?3 AND business_id = ?4`
        ).bind(name, clean(b.description).slice(0, 200), +b.id, biz.id).run();
      } else {
        await env.DB.prepare(
          `INSERT INTO business_services (business_id, name, description) VALUES (?1,?2,?3)`
        ).bind(biz.id, name, clean(b.description).slice(0, 200)).run();
      }
    } catch (e) {
      if (/no such table/i.test(String((e && e.message) || e))) {
        throw { status: 503, error: 'Services need the latest database update. Run npm run db:migrate, then try again.' };
      }
      throw e;
    }
    return ok(env, request);
  },

  /** Soft-delete: the service stops being offered but history keeps its name. */
  'POST /api/services/remove': async (request, env) => {
    const me = await requireMember(request, env);
    const { id } = await readJson(request);
    const row = await env.DB.prepare(`SELECT * FROM business_services WHERE id = ?1`).bind(+id).first();
    if (!row) throw { status: 404, error: 'Service not found.' };
    await ownBusiness(env, me, row.business_id);
    await env.DB.prepare(`UPDATE business_services SET active = 0 WHERE id = ?1`).bind(+id).run();
    return ok(env, request);
  },

  'POST /api/businesses/primary': async (request, env) => {
    const me = await requireMember(request, env);
    const { id } = await readJson(request);
    const owned = await ownBusiness(env, me, id);
    await env.DB.batch([
      env.DB.prepare(`UPDATE businesses SET is_primary = 0 WHERE member_id = ?1`).bind(me.id),
      env.DB.prepare(`UPDATE businesses SET is_primary = 1 WHERE id = ?1`).bind(owned.id)
    ]);
    return ok(env, request);
  },

  'POST /api/businesses/remove': async (request, env) => {
    const me = await requireMember(request, env);
    const { id } = await readJson(request);
    const owned = await ownBusiness(env, me, id);
    const count = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM businesses WHERE member_id = ?1 AND active = 1`
    ).bind(me.id).first();
    if ((count?.n || 0) < 2) throw { status: 400, error: 'Keep at least one business on your profile.' };
    await env.DB.prepare(`UPDATE businesses SET active = 0, is_primary = 0 WHERE id = ?1`).bind(owned.id).run();
    const remaining = await env.DB.prepare(
      `SELECT id FROM businesses WHERE member_id = ?1 AND active = 1 ORDER BY created_at LIMIT 1`
    ).bind(me.id).first();
    if (remaining) {
      await env.DB.prepare(`UPDATE businesses SET is_primary = 1 WHERE id = ?1`).bind(remaining.id).run();
    }
    return ok(env, request);
  },

  /* ---- opportunities ---- */

  'POST /api/opportunities': async (request, env) => {
    const me = await requireMember(request, env);
    const b = await readJson(request);
    const url = clean(b.facebookUrl);
    const platform = b.platform === 'nextdoor' ? 'nextdoor' : 'facebook';
    const PLATFORMS = {
      facebook: { label: 'Facebook', test: /^https:\/\/([\w-]+\.)*(facebook\.com|fb\.com|fb\.me)\/.+/i },
      // Nextdoor post paths vary; the host is what is validated.
      nextdoor: { label: 'Nextdoor', test: /^https:\/\/([\w-]+\.)*nextdoor\.[a-z.]{2,}\/.+/i }
    };
    if (!/^https:\/\//i.test(url)) throw { status: 400, error: 'The link must start with https://' };
    if (!PLATFORMS[platform].test.test(url)) {
      throw {
        status: 400,
        error: 'This link doesn’t look like a ' + PLATFORMS[platform].label
          + ' link. Please check the URL or change the platform.'
      };
    }
    const beneficiaryId = +b.beneficiaryId || me.id;
    const beneficiary = await env.DB.prepare(`SELECT * FROM members WHERE id = ?1 AND status = 'active'`)
      .bind(beneficiaryId).first();
    if (!beneficiary) throw { status: 400, error: 'That business is not an active member.' };

    const dupe = await env.DB.prepare(
      `SELECT id FROM opportunities WHERE facebook_url = ?1 AND archived_at IS NULL`
    ).bind(url).first();
    if (dupe && !b.force) throw { status: 409, error: 'This post has already been submitted.' };

    const sendForReview = !!b.sendForReview && beneficiaryId !== me.id;
    const cols = [beneficiaryId, +b.businessId || null,
                  clean(b.businessDisplayName) || beneficiary.full_name,
                  me.id, url, clean(b.facebookGroupName), clean(b.location),
                  sendForReview ? 'pending_review' : 'active', clean(b.reviewNote)];
    // Optional columns arrive with later migrations. Try the fullest insert
    // first and step down, so a database missing 007 (or 003/004) still accepts
    // the submission instead of failing.
    const extras = [clean(b.notes).slice(0, 300), +b.serviceId || null,
                    clean(b.serviceName).slice(0, 120)];
    const missingCol = e => /no such column|has no column/i.test(String((e && e.message) || e));
    let res;
    try {
      res = await env.DB.prepare(
        `INSERT INTO opportunities
           (beneficiary_id, business_id, business_display_name, submitted_by_id,
            facebook_url, facebook_group_name, location, status, review_note,
            opportunity_summary, service_id, service_name, platform)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)`
      ).bind(...cols, ...extras, platform).run();
    } catch (e) {
      if (!missingCol(e)) throw e;
      // Without the platform column a Nextdoor post would be saved and shown as
      // Facebook, so refuse it with an actionable message instead.
      if (platform === 'nextdoor') {
        throw {
          status: 503,
          error: 'Nextdoor posts need the latest database update. Run npm run db:migrate, then try again.'
        };
      }
      try {
        res = await env.DB.prepare(
          `INSERT INTO opportunities
             (beneficiary_id, business_id, business_display_name, submitted_by_id,
              facebook_url, facebook_group_name, location, status, review_note,
              opportunity_summary, service_id, service_name)
           VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)`
        ).bind(...cols, ...extras).run();
      } catch (e2) {
        if (!missingCol(e2)) throw e2;
        res = await env.DB.prepare(
          `INSERT INTO opportunities
             (beneficiary_id, business_id, business_display_name, submitted_by_id,
              facebook_url, facebook_group_name, location, status, review_note)
           VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)`
        ).bind(...cols).run();
      }
    }

    // Fan out one status row per active member, so "missed" is computable later.
    if (!sendForReview) await fanOut(env, res.meta.last_row_id, beneficiaryId);
    return ok(env, request, { id: res.meta.last_row_id });
  },

  'POST /api/opportunities/status': async (request, env) => {
    const me = await requireMember(request, env);
    const { opportunityId, status, reason } = await readJson(request);
    const allowed = ['open', 'completed', 'not_member', 'join_pending', 'banned', 'unable'];
    if (!allowed.includes(status)) throw { status: 400, error: 'Unknown status.' };
    const opp = await env.DB.prepare(`SELECT * FROM opportunities WHERE id = ?1`).bind(+opportunityId).first();
    if (!opp || opp.archived_at || opp.status !== 'active') throw { status: 404, error: 'Opportunity not available.' };
    if (opp.beneficiary_id === me.id) throw { status: 400, error: 'You cannot tag your own opportunity.' };
    const completedAt = status === 'completed' ? new Date().toISOString() : null;
    const unableReason = status === 'unable' ? clean(reason).slice(0, 300) || null : null;
    try {
      await env.DB.prepare(
        `INSERT INTO member_opportunity_status
           (opportunity_id, member_id, status, unable_reason, completed_at, status_changed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
         ON CONFLICT (opportunity_id, member_id) DO UPDATE SET
           status = excluded.status,
           unable_reason = excluded.unable_reason,
           completed_at = excluded.completed_at,
           status_changed_at = datetime('now')`
      ).bind(opp.id, me.id, status, unableReason, completedAt).run();
    } catch (e) {
      // Databases that have not yet had migrations/002_unable_reason.sql applied
      // have no unable_reason column and an older status CHECK constraint.
      // Everything except the new 'unable' status still works there, so fall
      // back rather than breaking completing a tag.
      const msg = String((e && e.message) || e);
      if (!/unable_reason|no such column/i.test(msg)) throw e;
      if (status === 'unable') {
        throw { status: 503, error: 'Saving a reason needs the latest database update. Run npm run db:migrate, then try again.' };
      }
      await env.DB.prepare(
        `INSERT INTO member_opportunity_status
           (opportunity_id, member_id, status, completed_at, status_changed_at)
         VALUES (?1, ?2, ?3, ?4, datetime('now'))
         ON CONFLICT (opportunity_id, member_id) DO UPDATE SET
           status = excluded.status,
           completed_at = excluded.completed_at,
           status_changed_at = datetime('now')`
      ).bind(opp.id, me.id, status, completedAt).run();
    }
    return ok(env, request);
  },

  /** Business owner decides on a post submitted for their review. */
  'POST /api/opportunities/review': async (request, env) => {
    const me = await requireMember(request, env);
    const { opportunityId, decision, reason } = await readJson(request);
    const opp = await env.DB.prepare(`SELECT * FROM opportunities WHERE id = ?1`).bind(+opportunityId).first();
    if (!opp) throw { status: 404, error: 'Not found.' };
    // Only the business owner (or an admin) may decide.
    if (opp.beneficiary_id !== me.id && me.role !== 'admin') throw { status: 403, error: 'Not your opportunity.' };
    // Approving only makes sense for a post still awaiting review. Declining is
    // also how a business owner pulls an already-published post out of tagging,
    // so 'active' is accepted there too.
    if (decision === 'approve' && opp.status !== 'pending_review') {
      throw { status: 400, error: 'This is not awaiting review.' };
    }
    if (decision !== 'approve' && !['pending_review', 'active'].includes(opp.status)) {
      throw { status: 400, error: 'This opportunity has already been reviewed.' };
    }

    if (decision === 'approve') {
      await env.DB.prepare(
        `UPDATE opportunities SET status = 'active', reviewed_by_id = ?1, reviewed_at = datetime('now') WHERE id = ?2`
      ).bind(me.id, opp.id).run();
      await fanOut(env, opp.id, opp.beneficiary_id);
    } else {
      await env.DB.prepare(
        `UPDATE opportunities SET status = 'declined', reviewed_by_id = ?1,
                                  reviewed_at = datetime('now'), decline_reason = ?2,
                                  archived_at = COALESCE(archived_at, datetime('now'))
          WHERE id = ?3`
      ).bind(me.id, clean(reason), opp.id).run();
    }
    return ok(env, request);
  },

  /* ---- saved comments (private per member) ---- */

  'POST /api/comments': async (request, env) => {
    const me = await requireMember(request, env);
    const b = await readJson(request);
    if (!clean(b.text)) throw { status: 400, error: 'Write the comment you want to save.' };
    if (b.id) {
      try {
        await env.DB.prepare(
          `UPDATE saved_comments SET business_member_id = ?1, label = ?2, text = ?3,
                                     service_id = ?4, updated_at = datetime('now')
            WHERE id = ?5 AND member_id = ?6`
        ).bind(+b.businessMemberId, clean(b.label), clean(b.text).slice(0, 500),
               +b.serviceId || null, +b.id, me.id).run();
      } catch (e) {
        if (!/service_id|no such column/i.test(String((e && e.message) || e))) throw e;
        await env.DB.prepare(
          `UPDATE saved_comments SET business_member_id = ?1, label = ?2, text = ?3, updated_at = datetime('now')
            WHERE id = ?4 AND member_id = ?5`
        ).bind(+b.businessMemberId, clean(b.label), clean(b.text).slice(0, 500), +b.id, me.id).run();
      }
    } else {
      try {
        await env.DB.prepare(
          `INSERT INTO saved_comments (member_id, business_member_id, label, text, service_id)
           VALUES (?1,?2,?3,?4,?5)`
        ).bind(me.id, +b.businessMemberId, clean(b.label), clean(b.text).slice(0, 500), +b.serviceId || null).run();
      } catch (e) {
        if (!/service_id|no such column/i.test(String((e && e.message) || e))) throw e;
        await env.DB.prepare(
          `INSERT INTO saved_comments (member_id, business_member_id, label, text) VALUES (?1,?2,?3,?4)`
        ).bind(me.id, +b.businessMemberId, clean(b.label), clean(b.text).slice(0, 500)).run();
      }
    }
    return ok(env, request);
  },

  'POST /api/comments/delete': async (request, env) => {
    const me = await requireMember(request, env);
    const { id } = await readJson(request);
    await env.DB.prepare(`DELETE FROM saved_comments WHERE id = ?1 AND member_id = ?2`).bind(+id, me.id).run();
    return ok(env, request);
  },

  /* ---- groups ---- */

  'POST /api/groups/status': async (request, env) => {
    const me = await requireMember(request, env);
    const { groupId, status } = await readJson(request);
    if (!['joined', 'not_joined', 'requested', 'unknown'].includes(status)) {
      throw { status: 400, error: 'Unknown status.' };
    }
    await env.DB.prepare(
      `INSERT INTO group_membership (group_id, member_id, status, updated_at)
       VALUES (?1,?2,?3, datetime('now'))
       ON CONFLICT (group_id, member_id) DO UPDATE SET status = excluded.status, updated_at = datetime('now')`
    ).bind(+groupId, me.id, status).run();
    return ok(env, request);
  },

  /* ---- announcements: members submit, admins publish ---- */

  'POST /api/announcements': async (request, env) => {
    const me = await requireMember(request, env);
    const { title, message } = await readJson(request);
    if (!clean(title) || !clean(message)) throw { status: 400, error: 'Add a title and a message.' };
    // A member submission is always pending, regardless of role. Admins publish
    // through /api/admin/announcements instead.
    const res = await env.DB.prepare(
      `INSERT INTO announcements (author_id, submitted_by_id, title, message, status)
       VALUES (?1, ?1, ?2, ?3, 'pending')`
    ).bind(me.id, clean(title).slice(0, 120), clean(message).slice(0, 2000)).run();
    return ok(env, request, { id: res.meta.last_row_id });
  },

  'POST /api/announcements/read': async (request, env) => {
    const me = await requireMember(request, env);
    const { ids } = await readJson(request);
    const list = Array.isArray(ids) ? ids.map(Number).filter(Boolean) : [];
    if (list.length) {
      await env.DB.batch(list.map(id => env.DB.prepare(
        `INSERT OR IGNORE INTO announcement_reads (announcement_id, member_id) VALUES (?1, ?2)`
      ).bind(id, me.id)));
    }
    return ok(env, request);
  },

  /** Dismiss = hide from MY Home screen. Everyone else still sees it. */
  'POST /api/announcements/dismiss': async (request, env) => {
    const me = await requireMember(request, env);
    const { id, dismissed } = await readJson(request);
    const on = dismissed !== false;
    try {
      await env.DB.prepare(
        `INSERT INTO announcement_reads (announcement_id, member_id, dismissed_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT (announcement_id, member_id) DO UPDATE SET dismissed_at = excluded.dismissed_at`
      ).bind(+id, me.id, on ? new Date().toISOString() : null).run();
    } catch (e) {
      if (/dismissed_at|no such column/i.test(String((e && e.message) || e))) {
        throw { status: 503, error: 'Dismissing needs the latest database update. Run npm run db:migrate, then try again.' };
      }
      throw e;
    }
    return ok(env, request);
  },

  /**
   * Dismiss a transient Home alert (currently opportunity review outcomes).
   * Per member; the opportunity and its review record are untouched.
   */
  'POST /api/alerts/dismiss': async (request, env) => {
    const me = await requireMember(request, env);
    const { kind, refId } = await readJson(request);
    const k = clean(kind).slice(0, 40);
    if (!k || !+refId) throw { status: 400, error: 'Nothing to dismiss.' };
    try {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO alert_dismissals (member_id, kind, ref_id) VALUES (?1, ?2, ?3)`
      ).bind(me.id, k, +refId).run();
    } catch (e) {
      if (!/no such table/i.test(String((e && e.message) || e))) throw e;
      throw { status: 503, error: 'Dismissing needs the latest database update. Run npm run db:migrate.' };
    }
    return ok(env, request);
  },

  /* ---- nudges: viewed and dismissed are separate states ---- */

  'POST /api/nudges/view': async (request, env) => {
    const me = await requireMember(request, env);
    const { ids } = await readJson(request);
    const list = Array.isArray(ids) ? ids.map(Number).filter(Boolean).slice(0, 50) : [];
    if (!list.length) return ok(env, request);
    try {
      await env.DB.batch(list.map(id => env.DB.prepare(
        `UPDATE nudges SET viewed_at = COALESCE(viewed_at, datetime('now'))
          WHERE id = ?1 AND recipient_id = ?2`
      ).bind(id, me.id)));
    } catch (e) {
      if (!/viewed_at|no such column/i.test(String((e && e.message) || e))) throw e;
      throw { status: 503, error: 'Nudge tracking needs the latest database update. Run npm run db:migrate.' };
    }
    return ok(env, request);
  },

  'POST /api/nudges/dismiss': async (request, env) => {
    const me = await requireMember(request, env);
    const { id } = await readJson(request);
    try {
      await env.DB.prepare(
        `UPDATE nudges SET viewed_at = COALESCE(viewed_at, datetime('now')),
                           dismissed_at = datetime('now')
          WHERE id = ?1 AND recipient_id = ?2`
      ).bind(+id, me.id).run();
    } catch (e) {
      if (!/dismissed_at|viewed_at|no such column/i.test(String((e && e.message) || e))) throw e;
      throw { status: 503, error: 'Nudge tracking needs the latest database update. Run npm run db:migrate.' };
    }
    return ok(env, request);
  },

  /* ================================ admin ================================= */

  'POST /api/admin/members': async (request, env) => {
    const admin = await requireAdmin(request, env);
    const b = await readJson(request);
    const addr = clean(b.email).toLowerCase();
    if (!isEmail(addr)) throw { status: 400, error: 'Enter a valid email address.' };
    // The Add Member form collects one person name (business owner name); older
    // clients may still send fullName. Either satisfies the requirement.
    const personName = clean(b.fullName) || clean(b.businessOwnerName);
    if (!personName) throw { status: 400, error: 'Enter the business owner’s name.' };
    const dupe = await env.DB.prepare(`SELECT id FROM members WHERE lower(email) = ?1`).bind(addr).first();
    if (dupe) throw { status: 409, error: 'Another member already uses that email address.' };

    // No password is created — the member sets their own via the reset email.
    const res = await env.DB.prepare(
      `INSERT INTO members (email, full_name, business_owner_name, role, status)
       VALUES (?1,?2,?3,'member','active')`
    ).bind(addr, personName, clean(b.businessOwnerName) || personName).run();

    if (clean(b.businessName)) {
      await env.DB.prepare(
        `INSERT INTO businesses (member_id, name, is_primary) VALUES (?1, ?2, 1)`
      ).bind(res.meta.last_row_id, clean(b.businessName)).run();
    }
    // No password is created. The member signs in with an email login code.
    let emailed = true, emailError = '';
    try {
      await issueLoginCode(env, { id: res.meta.last_row_id, email: addr });
    } catch (e) {
      emailed = false; emailError = String(e.message || e);
    }
    return ok(env, request, { id: res.meta.last_row_id, invited: emailed, emailError });
  },

  /**
   * Edit an existing member. Names live only on members / businesses, so every
   * screen picks the change up from the next bootstrap — no cached copies.
   */
  /** Run the nightly retention pass now. Same code path as the cron. */
  'POST /api/admin/retention/run': async (request, env) => {
    await requireAdmin(request, env);
    const summary = await runRetention(env, 'manual');
    return ok(env, request, { summary });
  },

  /** Recent retention runs — counts only, for diagnosing a failed cleanup. */
  'GET /api/admin/retention': async (request, env) => {
    await requireAdmin(request, env);
    let runs = { results: [] };
    try {
      runs = await env.DB.prepare(
        `SELECT id, ran_at, summary, ok, note FROM retention_runs ORDER BY ran_at DESC LIMIT 20`
      ).all();
    } catch (e) { runs = { results: [] }; }
    return ok(env, request, { runs: runs.results });
  },

  'POST /api/admin/members/update': async (request, env) => {
    await requireAdmin(request, env);
    const b = await readJson(request);
    const id = +b.id;
    const row = await env.DB.prepare(`SELECT * FROM members WHERE id = ?1`).bind(id).first();
    if (!row) throw { status: 404, error: 'That member no longer exists.' };

    const name = clean(b.businessOwnerName) || clean(b.fullName);
    if (!name) throw { status: 400, error: 'Enter the business owner’s name.' };
    const addr = clean(b.email).toLowerCase();
    if (addr) {
      if (!isEmail(addr)) throw { status: 400, error: 'Enter a valid email address.' };
      const dupe = await env.DB.prepare(
        `SELECT id FROM members WHERE lower(email) = ?1 AND id <> ?2`
      ).bind(addr, id).first();
      if (dupe) throw { status: 409, error: 'Another member already uses that email address.' };
    }
    // members.tag_group only permits these two values.
    const group = ['active', 'paused'].indexOf(clean(b.tagGroup)) > -1 ? clean(b.tagGroup) : null;

    await env.DB.prepare(
      `UPDATE members SET full_name = ?1, business_owner_name = ?1,
                          email = COALESCE(?2, email),
                          tag_group = COALESCE(?3, tag_group)
        WHERE id = ?4`
    ).bind(name.slice(0, 120), addr || null, group, id).run();

    const bizName = clean(b.businessName);
    if (bizName) {
      const primary = await env.DB.prepare(
        `SELECT id FROM businesses WHERE member_id = ?1 AND active = 1
          ORDER BY is_primary DESC, id ASC LIMIT 1`
      ).bind(id).first();
      if (primary) {
        await env.DB.prepare(`UPDATE businesses SET name = ?1 WHERE id = ?2`)
          .bind(bizName.slice(0, 120), primary.id).run();
      } else {
        await env.DB.prepare(`INSERT INTO businesses (member_id, name, is_primary) VALUES (?1, ?2, 1)`)
          .bind(id, bizName.slice(0, 120)).run();
      }
    }
    return ok(env, request);
  },

  'POST /api/admin/members/status': async (request, env) => {
    const admin = await requireAdmin(request, env);
    const { id, status } = await readJson(request);
    if (+id === admin.id) throw { status: 400, error: 'You cannot deactivate your own account.' };
    if (!['active', 'inactive'].includes(status)) throw { status: 400, error: 'Unknown status.' };
    await env.DB.prepare(`UPDATE members SET status = ?1 WHERE id = ?2`).bind(status, +id).run();
    if (status === 'inactive') {
      await env.DB.prepare(`DELETE FROM sessions WHERE member_id = ?1`).bind(+id).run();
    }
    return ok(env, request);
  },

  'POST /api/admin/members/role': async (request, env) => {
    const admin = await requireAdmin(request, env);
    const { id, role } = await readJson(request);
    if (!['member', 'admin'].includes(role)) throw { status: 400, error: 'Unknown role.' };
    if (+id === admin.id) throw { status: 400, error: 'You cannot change your own admin access.' };
    if (role === 'member') {
      const admins = await env.DB.prepare(
        `SELECT COUNT(*) AS n FROM members WHERE role = 'admin' AND status = 'active' AND id != ?1`
      ).bind(+id).first();
      if ((admins?.n || 0) < 1) throw { status: 400, error: 'The chapter must keep at least one administrator.' };
    }
    await env.DB.prepare(`UPDATE members SET role = ?1 WHERE id = ?2`).bind(role, +id).run();
    return ok(env, request);
  },

  'POST /api/admin/transfer': async (request, env) => {
    const admin = await requireAdmin(request, env);
    const { toMemberId } = await readJson(request);
    const target = await env.DB.prepare(`SELECT * FROM members WHERE id = ?1`).bind(+toMemberId).first();
    if (!target) throw { status: 404, error: 'Member not found.' };
    if (target.status !== 'active') throw { status: 400, error: 'That member is deactivated.' };
    if (target.id === admin.id) throw { status: 400, error: 'You already hold the admin role.' };
    await env.DB.batch([
      env.DB.prepare(`UPDATE members SET role = 'admin' WHERE id = ?1`).bind(target.id),
      env.DB.prepare(`UPDATE members SET role = 'member' WHERE id = ?1`).bind(admin.id),
      env.DB.prepare(`INSERT INTO role_transfers (from_member_id, to_member_id) VALUES (?1,?2)`)
        .bind(admin.id, target.id)
    ]);
    return ok(env, request);
  },

  'POST /api/admin/leadership': async (request, env) => {
    const admin = await requireAdmin(request, env);
    const { roleKey, memberId } = await readJson(request);
    const keys = ['president', 'vicePresident', 'chapterTech', 'ambassador'];
    if (!keys.includes(roleKey)) throw { status: 400, error: 'Unknown leadership role.' };
    await env.DB.prepare(
      `UPDATE leadership SET member_id = ?1, assigned_by = ?2, assigned_at = datetime('now') WHERE role_key = ?3`
    ).bind(memberId ? +memberId : null, admin.id, roleKey).run();
    return ok(env, request);
  },

  'POST /api/admin/announcements': async (request, env) => {
    const admin = await requireAdmin(request, env);
    const b = await readJson(request);
    // Blank expiry means the 30-day default, applied here so the rule lives on
    // the server rather than in whichever client happens to be talking to it.
    const expiresAt = expiryOrDefault(b.expiresAt);
    if (b.id) {
      try {
        await env.DB.prepare(
          `UPDATE announcements SET title = ?1, message = ?2, pinned = ?3,
                                    expires_at = ?4, updated_at = datetime('now')
            WHERE id = ?5`
        ).bind(clean(b.title), clean(b.message), b.pinned ? 1 : 0, expiresAt, +b.id).run();
      } catch (e) {
        if (!/expires_at|no such column/i.test(String((e && e.message) || e))) throw e;
        await env.DB.prepare(
          `UPDATE announcements SET title = ?1, message = ?2, pinned = ?3, updated_at = datetime('now') WHERE id = ?4`
        ).bind(clean(b.title), clean(b.message), b.pinned ? 1 : 0, +b.id).run();
      }
      return ok(env, request);
    }
    if (!clean(b.title) || !clean(b.message)) throw { status: 400, error: 'Add a title and a message.' };
    let res;
    try {
      res = await env.DB.prepare(
        `INSERT INTO announcements (author_id, submitted_by_id, title, message, status, pinned,
                                    approved_by_id, approved_at, published_at, expires_at)
         VALUES (?1, ?1, ?2, ?3, 'published', ?4, ?1, datetime('now'), datetime('now'), ?5)`
      ).bind(admin.id, clean(b.title).slice(0, 120), clean(b.message).slice(0, 2000),
             b.pinned ? 1 : 0, expiresAt).run();
    } catch (e) {
      if (!/published_at|expires_at|no such column/i.test(String((e && e.message) || e))) throw e;
      res = await env.DB.prepare(
        `INSERT INTO announcements (author_id, submitted_by_id, title, message, status, pinned,
                                    approved_by_id, approved_at)
         VALUES (?1, ?1, ?2, ?3, 'published', ?4, ?1, datetime('now'))`
      ).bind(admin.id, clean(b.title).slice(0, 120), clean(b.message).slice(0, 2000), b.pinned ? 1 : 0).run();
    }
    return ok(env, request, { id: res.meta.last_row_id });
  },

  'POST /api/admin/announcements/decide': async (request, env) => {
    const admin = await requireAdmin(request, env);
    const { id, decision, reason } = await readJson(request);
    const row = await env.DB.prepare(`SELECT * FROM announcements WHERE id = ?1`).bind(+id).first();
    if (!row) throw { status: 404, error: 'Not found.' };
    if (row.status !== 'pending') throw { status: 400, error: 'This submission was already handled.' };
    if (decision === 'approve') {
      try {
        await env.DB.prepare(
          `UPDATE announcements SET status = 'published', approved_by_id = ?1,
                                    approved_at = datetime('now'), published_at = datetime('now'),
                                    expires_at = COALESCE(expires_at, ?2)
            WHERE id = ?3`
        ).bind(admin.id, expiryOrDefault(''), row.id).run();
      } catch (e) {
        if (!/published_at|expires_at|no such column/i.test(String((e && e.message) || e))) throw e;
        await env.DB.prepare(
          `UPDATE announcements SET status = 'published', approved_by_id = ?1, approved_at = datetime('now')
            WHERE id = ?2`
        ).bind(admin.id, row.id).run();
      }
    } else {
      await env.DB.prepare(
        `UPDATE announcements SET status = 'declined', approved_by_id = ?1,
                                  approved_at = datetime('now'), decline_reason = ?2
          WHERE id = ?3`
      ).bind(admin.id, clean(reason), row.id).run();
    }
    return ok(env, request);
  },

  'POST /api/admin/announcements/pin': async (request, env) => {
    await requireAdmin(request, env);
    const { id, pinned } = await readJson(request);
    await env.DB.prepare(`UPDATE announcements SET pinned = ?1 WHERE id = ?2`).bind(pinned ? 1 : 0, +id).run();
    return ok(env, request);
  },

  'POST /api/admin/announcements/delete': async (request, env) => {
    await requireAdmin(request, env);
    const { id } = await readJson(request);
    await env.DB.prepare(`DELETE FROM announcements WHERE id = ?1`).bind(+id).run();
    return ok(env, request);
  },

  'POST /api/admin/nudge': async (request, env) => {
    const admin = await requireAdmin(request, env);
    const { memberId, message } = await readJson(request);
    const last = await env.DB.prepare(
      `SELECT created_at FROM nudges WHERE recipient_id = ?1 ORDER BY created_at DESC LIMIT 1`
    ).bind(+memberId).first();
    if (last && Date.now() - new Date(last.created_at.replace(' ', 'T') + 'Z').getTime() < NUDGE_COOLDOWN_MS) {
      throw { status: 429, error: 'That member was nudged in the last 24 hours.' };
    }
    await env.DB.prepare(
      `INSERT INTO nudges (sender_id, recipient_id, message) VALUES (?1,?2,?3)`
    ).bind(admin.id, +memberId, clean(message).slice(0, 200)).run();
    return ok(env, request);
  },

  'POST /api/admin/groups': async (request, env) => {
    await requireAdmin(request, env);
    const b = await readJson(request);
    if (!clean(b.name)) throw { status: 400, error: 'Enter the group name.' };
    if (b.id) {
      await env.DB.prepare(
        `UPDATE fb_groups SET name=?1, url=?2, category=?3, city=?4, county=?5, state=?6,
                              nationwide=?7, featured=?8, sort_order=?9
          WHERE id=?10`
      ).bind(clean(b.name), clean(b.url), clean(b.category), clean(b.city), clean(b.county),
             clean(b.state), b.nationwide ? 1 : 0, b.featured ? 1 : 0, +b.sortOrder || 0, +b.id).run();
      return ok(env, request);
    }
    const res = await env.DB.prepare(
      `INSERT INTO fb_groups (name, url, category, city, county, state, nationwide, featured, sort_order)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)`
    ).bind(clean(b.name), clean(b.url), clean(b.category), clean(b.city), clean(b.county),
           clean(b.state), b.nationwide ? 1 : 0, b.featured ? 1 : 0, +b.sortOrder || 0).run();
    return ok(env, request, { id: res.meta.last_row_id });
  },

  'POST /api/admin/groups/delete': async (request, env) => {
    await requireAdmin(request, env);
    const { id } = await readJson(request);
    await env.DB.prepare(`DELETE FROM fb_groups WHERE id = ?1`).bind(+id).run();
    return ok(env, request);
  },

  'POST /api/admin/opportunities/archive': async (request, env) => {
    await requireAdmin(request, env);
    const { id, archived } = await readJson(request);
    await env.DB.prepare(`UPDATE opportunities SET archived_at = ?1 WHERE id = ?2`)
      .bind(archived ? new Date().toISOString() : null, +id).run();
    return ok(env, request);
  },

  'POST /api/admin/members/reset': async (request, env) => {
    await requireAdmin(request, env);
    const { id } = await readJson(request);
    const member = await env.DB.prepare(`SELECT * FROM members WHERE id = ?1`).bind(+id).first();
    if (!member) throw { status: 404, error: 'Member not found.' };
    await issueReset(env, member, !member.password_hash);
    return ok(env, request);
  }
};

/* ---------------------------------------------------------------- helpers --- */

async function ownBusiness(env, me, id) {
  const row = await env.DB.prepare(`SELECT * FROM businesses WHERE id = ?1 AND active = 1`).bind(+id).first();
  if (!row) throw { status: 404, error: 'Business not found.' };
  if (row.member_id !== me.id && me.role !== 'admin') throw { status: 403, error: 'Not your business.' };
  return row;
}

/** ISO expiry: the admin's date when given, otherwise 30 days from now. */
function expiryOrDefault(value) {
  const raw = clean(value);
  if (raw) {
    const t = Date.parse(raw);
    if (t) return new Date(t).toISOString();
  }
  return new Date(Date.now() + 30 * 864e5).toISOString();
}

/**
 * Reconcile the service list submitted alongside a business. Undefined means
 * "not managed in this request", so older clients cannot wipe services.
 * Removed services are deactivated, never deleted, so history keeps its names.
 */
async function writeServices(env, businessId, services) {
  if (!Array.isArray(services)) return;
  try {
    const existing = await env.DB.prepare(
      `SELECT * FROM business_services WHERE business_id = ?1`
    ).bind(businessId).all();
    const rows = existing.results || [];
    const keep = new Set();
    const stmts = [];
    for (const sv of services.slice(0, 30)) {
      const name = clean(sv && sv.name).slice(0, 80);
      if (!name) continue;
      const byId = sv && sv.id ? rows.find(r => r.id === +sv.id) : null;
      const match = byId || rows.find(r => r.name.toLowerCase() === name.toLowerCase());
      if (match) {
        keep.add(match.id);
        stmts.push(env.DB.prepare(
          `UPDATE business_services SET name = ?1, active = 1 WHERE id = ?2`
        ).bind(name, match.id));
      } else {
        stmts.push(env.DB.prepare(
          `INSERT INTO business_services (business_id, name) VALUES (?1, ?2)`
        ).bind(businessId, name));
      }
    }
    for (const r of rows) {
      if (r.active && !keep.has(r.id)) {
        stmts.push(env.DB.prepare(`UPDATE business_services SET active = 0 WHERE id = ?1`).bind(r.id));
      }
    }
    if (stmts.length) await env.DB.batch(stmts);
  } catch (e) {
    if (/no such table|no such column/i.test(String((e && e.message) || e))) return;
    throw e;
  }
}

async function writePrefs(env, businessId, body) {
  const kinds = [['wants', 'want'], ['notWants', 'not_want'],
                 ['preferred', 'preferred_area'], ['avoid', 'avoid_area']];
  const stmts = [env.DB.prepare(`DELETE FROM business_preferences WHERE business_id = ?1`).bind(businessId)];
  for (const [field, kind] of kinds) {
    const list = Array.isArray(body[field]) ? body[field] : [];
    for (const value of list.map(clean).filter(Boolean).slice(0, 40)) {
      stmts.push(env.DB.prepare(
        `INSERT INTO business_preferences (business_id, kind, value) VALUES (?1,?2,?3)`
      ).bind(businessId, kind, value.slice(0, 60)));
    }
  }
  await env.DB.batch(stmts);
}

/** One status row per active member except the beneficiary. */
async function fanOut(env, opportunityId, beneficiaryId) {
  const members = await env.DB.prepare(
    `SELECT id FROM members WHERE status = 'active' AND id != ?1`
  ).bind(beneficiaryId).all();
  if (!members.results.length) return;
  await env.DB.batch(members.results.map(m => env.DB.prepare(
    `INSERT OR IGNORE INTO member_opportunity_status (opportunity_id, member_id, status)
     VALUES (?1, ?2, 'open')`
  ).bind(opportunityId, m.id)));
}

/* =========================== data retention ============================== *
 * One scheduled job, once a day. Every step is a bounded, indexed date-range
 * delete and is safe to run repeatedly: re-running finds nothing left to do.
 *
 * Ordering matters and is deliberate:
 *   1. snapshot every closed month into monthly_participation
 *   2. roll old nudge rows into nudge_stats
 *   3. archive fully-resolved opportunities
 *   4. delete expired auth rows and stale per-member state
 *   5. purge archived opportunities older than 12 months, and ONLY those whose
 *      months are all snapshotted, so history can never shift underneath us
 *
 * Never touched: members, businesses, services, saved comments, leadership,
 * group membership, settings, active announcements, active nudges, open
 * opportunities, monthly_participation, nudge_stats.
 * ------------------------------------------------------------------------- */

const RETENTION = {
  alertDismissalDays: 60,   // opportunity review alert records
  annDismissDays: 30,       // per-member announcement dismissals
  nudgeDismissDays: 30,     // dismissed nudges (aggregate kept)
  authDays: 3,              // spent/expired login codes and sessions
  staleStateDays: 30,       // stale per-member notification-ish rows
  archiveAfterDays: 30,     // fully-resolved posts become archived
  purgeMonths: 12           // archived posts may then be purged
};

const monthKeyOf = iso => String(iso || '').slice(0, 7);

/**
 * Past months with activity that have NOT been snapshotted yet, oldest first.
 * A month already carrying closed_at is deliberately excluded: once written,
 * a snapshot is frozen, so later cleanup can never recompute it from the
 * smaller data set it leaves behind.
 */
async function closableMonths(env) {
  const current = new Date().toISOString().slice(0, 7);
  const [rows, closed] = await Promise.all([
    env.DB.prepare(
      `SELECT DISTINCT substr(created_at,1,7) AS m FROM opportunities
        UNION SELECT DISTINCT substr(completed_at,1,7) FROM member_opportunity_status
         WHERE completed_at IS NOT NULL`
    ).all(),
    env.DB.prepare(
      `SELECT DISTINCT month_key AS m FROM monthly_participation WHERE closed_at IS NOT NULL`
    ).all()
  ]);
  const done = new Set((closed.results || []).map(r => r.m));
  return (rows.results || [])
    .map(r => r.m)
    .filter(m => m && m < current && !done.has(m))
    .sort();
}

/**
 * Write (or refresh) the ranking snapshot for one closed month. Computed from
 * the same rules the app uses: tags by completion date, posts by submission
 * date. Idempotent — re-running a month rewrites identical numbers.
 */
async function snapshotMonth(env, monthKey) {
  const goalRow = await env.DB.prepare(`SELECT value FROM settings WHERE key = 'monthly_tag_goal'`).first();
  const goal = +((goalRow && goalRow.value) || 25);
  // These four definitions mirror statsPeriod() in the app exactly. If one
  // changes there, change it here too, or a month's numbers will visibly shift
  // the moment it flips from live computation to its snapshot.
  //   tags       completed status rows, by completion date
  //   posts      published, non-archived opportunities, by submission date
  //   eligible   cohort rows, excluding every "unable" family status
  //   missed     cohort rows still not completed
  const rows = await env.DB.prepare(
    `SELECT m.id AS member_id,
            (SELECT COUNT(*) FROM member_opportunity_status s
              WHERE s.member_id = m.id AND s.status = 'completed'
                AND substr(s.completed_at,1,7) = ?1)                       AS tags_completed,
            (SELECT COUNT(*) FROM opportunities o
              WHERE o.submitted_by_id = m.id AND o.status = 'active'
                AND o.archived_at IS NULL
                AND substr(o.created_at,1,7) = ?1)                         AS posts_found,
            (SELECT COUNT(*) FROM member_opportunity_status s
              WHERE s.member_id = m.id
                AND s.status NOT IN ('not_member','join_pending','banned','unable')
                AND substr(s.eligible_from,1,7) = ?1)                      AS eligible,
            (SELECT COUNT(*) FROM member_opportunity_status s
              WHERE s.member_id = m.id
                AND s.status NOT IN ('not_member','join_pending','banned','unable','completed')
                AND substr(s.eligible_from,1,7) = ?1)                      AS missed
       FROM members m`
  ).bind(monthKey).all();

  const list = (rows.results || []).slice().sort((a, b) =>
    b.tags_completed - a.tags_completed || b.posts_found - a.posts_found || a.member_id - b.member_id);
  let rank = 0, prev = null;
  const stmts = list.map((r, i) => {
    if (r.tags_completed !== prev) { rank = i + 1; prev = r.tags_completed; }
    // DO NOTHING, never DO UPDATE: an existing snapshot row is history and is
    // never rewritten. Re-running the job is therefore a no-op for that month.
    return env.DB.prepare(
      `INSERT INTO monthly_participation
         (month_key, member_id, tags_completed, posts_found, eligible, missed, rank, goal, closed_at)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8, datetime('now'))
       ON CONFLICT (month_key, member_id) DO NOTHING`
    ).bind(monthKey, r.member_id, r.tags_completed, r.posts_found, r.eligible, r.missed, rank, goal);
  });
  if (stmts.length) await env.DB.batch(stmts);
  return stmts.length;
}

/** True when every month this opportunity touches already has a snapshot. */
async function monthsSnapshotted(env, opp) {
  const months = new Set([monthKeyOf(opp.created_at)]);
  if (opp.completed_at) months.add(monthKeyOf(opp.completed_at));
  if (opp.archived_at) months.add(monthKeyOf(opp.archived_at));
  const done = await env.DB.prepare(
    `SELECT DISTINCT substr(completed_at,1,7) AS m FROM member_opportunity_status
      WHERE opportunity_id = ?1 AND completed_at IS NOT NULL`
  ).bind(opp.id).all();
  (done.results || []).forEach(r => r.m && months.add(r.m));
  for (const m of months) {
    const snap = await env.DB.prepare(
      `SELECT 1 FROM monthly_participation WHERE month_key = ?1 AND closed_at IS NOT NULL LIMIT 1`
    ).bind(m).first();
    if (!snap) return false;
  }
  return true;
}

/**
 * The nightly retention pass. Returns the counts it acted on; throws only on
 * unexpected errors (a missing column from an unapplied migration is skipped,
 * not fatal, so an out-of-date database still gets the cleanup it can do).
 */
async function retentionSweep(env) {
  const out = {
    monthsSnapshotted: 0, nudgesAggregated: 0, opportunitiesArchived: 0,
    loginCodes: 0, sessions: 0, resetTokens: 0, resetRequests: 0,
    alertDismissals: 0, announcementStatus: 0, nudges: 0,
    staleStatusRows: 0, opportunitiesPurged: 0, skipped: []
  };
  const D = RETENTION;
  // A step whose table/column predates its migration is skipped, never fatal.
  const step = async (name, fn) => {
    try { return await fn(); }
    catch (e) {
      if (/no such table|no such column/i.test(String((e && e.message) || e))) {
        out.skipped.push(name);
        return 0;
      }
      throw e;
    }
  };
  const del = (name, sql, binds) => step(name, async () => {
    const res = await env.DB.prepare(sql).bind(...(binds || [])).run();
    return (res.meta && res.meta.changes) || 0;
  });

  /* 1. history first — nothing below can shift a past month afterwards */
  await step('snapshot', async () => {
    for (const m of await closableMonths(env)) {
      await snapshotMonth(env, m);
      out.monthsSnapshotted++;
    }
  });

  /* 2. aggregate nudges before their rows go */
  out.nudgesAggregated = await step('nudgeStats', async () => {
    const res = await env.DB.prepare(
      `INSERT INTO nudge_stats (month_key, recipient_id, sent, viewed, dismissed)
       SELECT substr(created_at,1,7), recipient_id, COUNT(*),
              SUM(CASE WHEN viewed_at IS NOT NULL THEN 1 ELSE 0 END),
              SUM(CASE WHEN dismissed_at IS NOT NULL THEN 1 ELSE 0 END)
         FROM nudges
        GROUP BY substr(created_at,1,7), recipient_id
       ON CONFLICT (month_key, recipient_id) DO UPDATE SET
         sent = excluded.sent, viewed = excluded.viewed, dismissed = excluded.dismissed`
    ).run();
    return (res.meta && res.meta.changes) || 0;
  });

  /* 3. archive posts nobody can act on any more (never deletes them) */
  out.opportunitiesArchived = await step('archive', async () => {
    const res = await env.DB.prepare(
      `UPDATE opportunities
          SET archived_at = datetime('now'),
              completed_at = COALESCE(completed_at, (
                SELECT MAX(COALESCE(s.completed_at, s.status_changed_at))
                  FROM member_opportunity_status s WHERE s.opportunity_id = opportunities.id))
        WHERE archived_at IS NULL
          AND status = 'active'
          AND created_at < datetime('now', ?1)
          AND EXISTS (SELECT 1 FROM member_opportunity_status s WHERE s.opportunity_id = opportunities.id)
          AND NOT EXISTS (SELECT 1 FROM member_opportunity_status s
                           WHERE s.opportunity_id = opportunities.id AND s.status = 'open')`
    ).bind('-' + D.archiveAfterDays + ' days').run();
    return (res.meta && res.meta.changes) || 0;
  });

  /* 4. expired auth material and stale per-member state */
  out.loginCodes = await del('loginCodes',
    `DELETE FROM login_codes
      WHERE (used_at IS NOT NULL AND used_at < datetime('now', ?1))
         OR expires_at < datetime('now', ?1)`, ['-' + D.authDays + ' days']);
  out.sessions = await del('sessions',
    `DELETE FROM sessions WHERE expires_at < datetime('now', ?1)`, ['-' + D.authDays + ' days']);
  out.resetTokens = await del('resetTokens',
    `DELETE FROM reset_tokens
      WHERE (used_at IS NOT NULL AND used_at < datetime('now', ?1))
         OR expires_at < datetime('now', ?1)`, ['-' + D.authDays + ' days']);
  out.resetRequests = await del('resetRequests',
    `DELETE FROM reset_requests WHERE created_at < datetime('now','-1 day')`);

  // Review-alert dismissals: the alert stops rendering after 24 hours anyway,
  // so after 60 days the record has no job left. The opportunity and its
  // review decision are untouched.
  out.alertDismissals = await del('alertDismissals',
    `DELETE FROM alert_dismissals WHERE dismissed_at < datetime('now', ?1)`,
    ['-' + D.alertDismissalDays + ' days']);

  // Per-member announcement rows: only dismissed ones, and only where the
  // announcement itself is already expired, so a live announcement never
  // reappears for someone who cleared it.
  out.announcementStatus = await del('announcementStatus',
    `DELETE FROM announcement_reads
      WHERE dismissed_at IS NOT NULL
        AND dismissed_at < datetime('now', ?1)
        AND announcement_id IN (
          SELECT id FROM announcements
           WHERE COALESCE(expires_at,
                          datetime(COALESCE(published_at, approved_at, created_at), '+30 days'))
                 < datetime('now'))`,
    ['-' + D.annDismissDays + ' days']);

  // Dismissed nudges only. Unread and viewed-but-active nudges stay.
  out.nudges = await del('nudges',
    `DELETE FROM nudges WHERE dismissed_at IS NOT NULL AND dismissed_at < datetime('now', ?1)`,
    ['-' + D.nudgeDismissDays + ' days']);

  // Orphaned per-member rows whose opportunity is already gone.
  out.staleStatusRows = await del('staleStatusRows',
    `DELETE FROM member_opportunity_status
      WHERE opportunity_id NOT IN (SELECT id FROM opportunities)`);

  /* 5. purge long-archived posts, one at a time, snapshot-checked */
  await step('purge', async () => {
    const old = await env.DB.prepare(
      `SELECT id, created_at, completed_at, archived_at FROM opportunities
        WHERE archived_at IS NOT NULL
          AND archived_at < datetime('now', ?1)
          AND NOT EXISTS (SELECT 1 FROM member_opportunity_status s
                           WHERE s.opportunity_id = opportunities.id AND s.status = 'open')
        ORDER BY archived_at LIMIT 200`
    ).bind('-' + D.purgeMonths + ' months').all();
    for (const o of (old.results || [])) {
      if (!(await monthsSnapshotted(env, o))) continue;
      // Children first, then the row itself, in one batch — an interrupted run
      // can never leave status rows pointing at a deleted opportunity.
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM member_opportunity_status WHERE opportunity_id = ?1`).bind(o.id),
        env.DB.prepare(`DELETE FROM alert_dismissals WHERE kind = 'opp_review' AND ref_id = ?1`).bind(o.id),
        env.DB.prepare(`DELETE FROM opportunities WHERE id = ?1`).bind(o.id)
      ]);
      out.opportunitiesPurged++;
    }
  });

  return out;
}

/** Run the retention pass, record the outcome, and log a readable summary. */
async function runRetention(env, trigger) {
  let summary, ok = 1, note = '';
  try {
    summary = await retentionSweep(env);
  } catch (e) {
    ok = 0;
    note = String((e && e.message) || e).slice(0, 300);
    summary = { failed: true };
  }
  const lines = Object.keys(summary)
    .filter(k => k !== 'skipped' && summary[k])
    .map(k => '  - ' + k + ': ' + summary[k]);
  console.log('Retention cleanup (' + (trigger || 'cron') + ')'
    + (lines.length ? '\n' + lines.join('\n') : '\n  - nothing to clean')
    + (summary.skipped && summary.skipped.length
        ? '\n  - skipped (migration not applied): ' + summary.skipped.join(', ') : '')
    + (ok ? '' : '\n  - FAILED: ' + note));
  try {
    await env.DB.prepare(
      `INSERT INTO retention_runs (summary, ok, note) VALUES (?1, ?2, ?3)`
    ).bind(JSON.stringify(summary), ok, note).run();
  } catch (e) { /* migrations/008 not applied yet — the console log still stands */ }
  return summary;
}

/* ------------------------------------------------------------------ entry --- */

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }
    const url = new URL(request.url);
    const key = `${request.method} ${url.pathname.replace(/\/$/, '')}`;
    const handler = routes[key];

    if (!handler) return fail(env, request, 404, 'Unknown endpoint');

    // Reject cross-origin writes from anywhere but the configured app origin.
    if (request.method !== 'GET') {
      const origin = request.headers.get('Origin');
      const allowed = (env.APP_ORIGIN || '').split(',').map(s => s.trim());
      if (origin && !allowed.includes(origin)) return fail(env, request, 403, 'Origin not allowed');
    }

    try {
      // No cleanup on the request path: retention is a single daily cron job.
      return await handler(request, env);
    } catch (e) {
      if (e && e.status) return fail(env, request, e.status, e.error);
      console.error('unhandled', e && (e.stack || e.message || e));
      return fail(env, request, 500, 'Something went wrong on the server.');
    }
  },

  /**
   * Daily cron (see wrangler.toml [triggers]). Snapshots closed months so
   * historical rankings are fixed, then applies the retention rules.
   */
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runRetention(env, 'cron'));
  }
};
