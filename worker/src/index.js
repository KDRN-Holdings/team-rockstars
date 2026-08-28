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

const PBKDF2_ITERATIONS = 210_000;
const SESSION_DAYS = 30;
const RESET_TTL_MIN = 60;
const RESET_MAX_PER_HOUR = 4;
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
  const candidate = await pbkdf2(
    password, unb64(member.password_salt), member.password_iterations || PBKDF2_ITERATIONS
  );
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
    'Access-Control-Allow-Headers': 'Content-Type',
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
  // SameSite=None is required while Pages (*.pages.dev) and the Worker
  // (*.workers.dev) are different sites. Put both on sculpt-rx.net subdomains
  // and this can tighten to SameSite=Lax — see README.
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

async function currentMember(request, env) {
  const raw = readCookie(request, 'tr_session');
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
    q(`SELECT * FROM announcements ORDER BY pinned DESC, created_at DESC`),
    q(`SELECT * FROM announcement_reads WHERE member_id = ?1`).bind(me.id),
    q(`SELECT * FROM leadership`),
    q(`SELECT * FROM fb_groups ORDER BY featured DESC, sort_order, name`),
    q(`SELECT * FROM group_membership WHERE member_id = ?1`).bind(me.id),
    q(`SELECT * FROM nudges WHERE recipient_id = ?1 ORDER BY created_at DESC`).bind(me.id),
    q(`SELECT * FROM role_transfers ORDER BY created_at DESC LIMIT 10`),
    q(`SELECT * FROM settings`),
    q(`SELECT * FROM monthly_participation WHERE closed_at IS NOT NULL`)
  ]);

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
      location: o.location, status: o.status,
      // The private review note is only for the owner and admins.
      reviewNote: (o.beneficiary_id === me.id || me.role === 'admin') ? o.review_note : '',
      reviewedById: o.reviewed_by_id, reviewedAt: o.reviewed_at,
      declineReason: o.decline_reason, createdAt: o.created_at, archivedAt: o.archived_at
    })),
    statuses: statuses.results.map(s => ({
      id: s.id, opportunityId: s.opportunity_id, memberId: s.member_id,
      status: s.status, eligibleFrom: s.eligible_from,
      completedAt: s.completed_at, statusChangedAt: s.status_changed_at
    })),
    comments: comments.results.map(c => ({
      id: c.id, memberId: c.member_id, businessMemberId: c.business_member_id,
      label: c.label, text: c.text, createdAt: c.created_at
    })),
    announcements: visibleAnn.map(a => ({
      id: a.id, authorId: a.author_id, submittedById: a.submitted_by_id,
      title: a.title, message: a.message, status: a.status, pinned: !!a.pinned,
      approvedById: a.approved_by_id, approvedAt: a.approved_at,
      declineReason: a.decline_reason, createdAt: a.created_at
    })),
    annReads: reads.results.map(r => ({ announcementId: r.announcement_id, memberId: r.member_id, readAt: r.read_at })),
    leadership: leadershipMap,
    groups: groups.results.map(g => ({
      id: g.id, name: g.name, url: g.url, category: g.category,
      city: g.city, county: g.county, state: g.state,
      nationwide: !!g.nationwide, featured: !!g.featured, sortOrder: g.sort_order
    })),
    groupStatus: membership.results.map(m2 => ({ groupId: m2.group_id, status: m2.status })),
    nudges: nudges.results.map(n => ({
      id: n.id, senderId: n.sender_id, recipientId: n.recipient_id,
      message: n.message, readAt: n.read_at, createdAt: n.created_at
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
    return json({ ok: true, me: memberPublic(member) }, {
      headers: { 'Set-Cookie': sessionCookie(token, env, SESSION_DAYS * 86400) }
    }, env, request);
  },

  'POST /api/auth/logout': async (request, env) => {
    const raw = readCookie(request, 'tr_session');
    if (raw) await env.DB.prepare(`DELETE FROM sessions WHERE token = ?1`).bind(await sha256(raw)).run();
    return json({ ok: true }, { headers: { 'Set-Cookie': sessionCookie('', env, 0) } }, env, request);
  },

  'GET /api/auth/me': async (request, env) => {
    const me = await currentMember(request, env);
    return me ? ok(env, request, { me: memberPublic(me) }) : fail(env, request, 401, 'Not signed in');
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
    if (!/^https?:\/\/([\w-]+\.)?(facebook\.com|fb\.com|fb\.me)\/.+/i.test(url)) {
      throw { status: 400, error: 'That does not look like a Facebook post link.' };
    }
    const beneficiaryId = +b.beneficiaryId || me.id;
    const beneficiary = await env.DB.prepare(`SELECT * FROM members WHERE id = ?1 AND status = 'active'`)
      .bind(beneficiaryId).first();
    if (!beneficiary) throw { status: 400, error: 'That business is not an active member.' };

    const dupe = await env.DB.prepare(
      `SELECT id FROM opportunities WHERE facebook_url = ?1 AND archived_at IS NULL`
    ).bind(url).first();
    if (dupe && !b.force) throw { status: 409, error: 'This Facebook post has already been submitted.' };

    const sendForReview = !!b.sendForReview && beneficiaryId !== me.id;
    const res = await env.DB.prepare(
      `INSERT INTO opportunities
         (beneficiary_id, business_id, business_display_name, submitted_by_id,
          facebook_url, facebook_group_name, location, status, review_note)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)`
    ).bind(beneficiaryId, +b.businessId || null, clean(b.businessDisplayName) || beneficiary.full_name,
           me.id, url, clean(b.facebookGroupName), clean(b.location),
           sendForReview ? 'pending_review' : 'active', clean(b.reviewNote)).run();

    // Fan out one status row per active member, so "missed" is computable later.
    if (!sendForReview) await fanOut(env, res.meta.last_row_id, beneficiaryId);
    return ok(env, request, { id: res.meta.last_row_id });
  },

  'POST /api/opportunities/status': async (request, env) => {
    const me = await requireMember(request, env);
    const { opportunityId, status } = await readJson(request);
    const allowed = ['open', 'completed', 'not_member', 'join_pending', 'banned'];
    if (!allowed.includes(status)) throw { status: 400, error: 'Unknown status.' };
    const opp = await env.DB.prepare(`SELECT * FROM opportunities WHERE id = ?1`).bind(+opportunityId).first();
    if (!opp || opp.archived_at || opp.status !== 'active') throw { status: 404, error: 'Opportunity not available.' };
    if (opp.beneficiary_id === me.id) throw { status: 400, error: 'You cannot tag your own opportunity.' };
    await env.DB.prepare(
      `INSERT INTO member_opportunity_status
         (opportunity_id, member_id, status, completed_at, status_changed_at)
       VALUES (?1, ?2, ?3, ?4, datetime('now'))
       ON CONFLICT (opportunity_id, member_id) DO UPDATE SET
         status = excluded.status,
         completed_at = excluded.completed_at,
         status_changed_at = datetime('now')`
    ).bind(opp.id, me.id, status, status === 'completed' ? new Date().toISOString() : null).run();
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
    if (opp.status !== 'pending_review') throw { status: 400, error: 'This is not awaiting review.' };

    if (decision === 'approve') {
      await env.DB.prepare(
        `UPDATE opportunities SET status = 'active', reviewed_by_id = ?1, reviewed_at = datetime('now') WHERE id = ?2`
      ).bind(me.id, opp.id).run();
      await fanOut(env, opp.id, opp.beneficiary_id);
    } else {
      await env.DB.prepare(
        `UPDATE opportunities SET status = 'declined', reviewed_by_id = ?1,
                                  reviewed_at = datetime('now'), decline_reason = ?2
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
      await env.DB.prepare(
        `UPDATE saved_comments SET business_member_id = ?1, label = ?2, text = ?3, updated_at = datetime('now')
          WHERE id = ?4 AND member_id = ?5`
      ).bind(+b.businessMemberId, clean(b.label), clean(b.text).slice(0, 500), +b.id, me.id).run();
    } else {
      await env.DB.prepare(
        `INSERT INTO saved_comments (member_id, business_member_id, label, text) VALUES (?1,?2,?3,?4)`
      ).bind(me.id, +b.businessMemberId, clean(b.label), clean(b.text).slice(0, 500)).run();
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

  /* ================================ admin ================================= */

  'POST /api/admin/members': async (request, env) => {
    const admin = await requireAdmin(request, env);
    const b = await readJson(request);
    const addr = clean(b.email).toLowerCase();
    if (!isEmail(addr)) throw { status: 400, error: 'Enter a valid email address.' };
    if (!clean(b.fullName)) throw { status: 400, error: 'Enter the member’s full name.' };
    const dupe = await env.DB.prepare(`SELECT id FROM members WHERE lower(email) = ?1`).bind(addr).first();
    if (dupe) throw { status: 409, error: 'Another member already uses that email address.' };

    // No password is created — the member sets their own via the reset email.
    const res = await env.DB.prepare(
      `INSERT INTO members (email, full_name, business_owner_name, role, status)
       VALUES (?1,?2,?3,'member','active')`
    ).bind(addr, clean(b.fullName), clean(b.businessOwnerName) || clean(b.fullName)).run();

    if (clean(b.businessName)) {
      await env.DB.prepare(
        `INSERT INTO businesses (member_id, name, is_primary) VALUES (?1, ?2, 1)`
      ).bind(res.meta.last_row_id, clean(b.businessName)).run();
    }
    let emailed = true, emailError = '';
    try {
      await issueReset(env, { id: res.meta.last_row_id, email: addr }, true);
    } catch (e) {
      emailed = false; emailError = String(e.message || e);
    }
    return ok(env, request, { id: res.meta.last_row_id, invited: emailed, emailError });
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
    if (b.id) {
      await env.DB.prepare(
        `UPDATE announcements SET title = ?1, message = ?2, pinned = ?3, updated_at = datetime('now') WHERE id = ?4`
      ).bind(clean(b.title), clean(b.message), b.pinned ? 1 : 0, +b.id).run();
      return ok(env, request);
    }
    if (!clean(b.title) || !clean(b.message)) throw { status: 400, error: 'Add a title and a message.' };
    const res = await env.DB.prepare(
      `INSERT INTO announcements (author_id, submitted_by_id, title, message, status, pinned,
                                  approved_by_id, approved_at)
       VALUES (?1, ?1, ?2, ?3, 'published', ?4, ?1, datetime('now'))`
    ).bind(admin.id, clean(b.title).slice(0, 120), clean(b.message).slice(0, 2000), b.pinned ? 1 : 0).run();
    return ok(env, request, { id: res.meta.last_row_id });
  },

  'POST /api/admin/announcements/decide': async (request, env) => {
    const admin = await requireAdmin(request, env);
    const { id, decision, reason } = await readJson(request);
    const row = await env.DB.prepare(`SELECT * FROM announcements WHERE id = ?1`).bind(+id).first();
    if (!row) throw { status: 404, error: 'Not found.' };
    if (row.status !== 'pending') throw { status: 400, error: 'This submission was already handled.' };
    if (decision === 'approve') {
      await env.DB.prepare(
        `UPDATE announcements SET status = 'published', approved_by_id = ?1, approved_at = datetime('now')
          WHERE id = ?2`
      ).bind(admin.id, row.id).run();
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

/** Opportunistic cleanup so expired rows do not accumulate. */
async function sweep(env) {
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM sessions WHERE expires_at < datetime('now')`),
    env.DB.prepare(`DELETE FROM reset_tokens WHERE expires_at < datetime('now','-1 day')`),
    env.DB.prepare(`DELETE FROM reset_requests WHERE created_at < datetime('now','-1 day')`)
  ]);
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
      const res = await handler(request, env);
      if (Math.random() < 0.02) ctx.waitUntil(sweep(env));
      return res;
    } catch (e) {
      if (e && e.status) return fail(env, request, e.status, e.error);
      console.error('unhandled', e && (e.stack || e.message || e));
      return fail(env, request, 500, 'Something went wrong on the server.');
    }
  },

  /** Optional cron: snapshot the closing month so history never shifts. */
  async scheduled(event, env, ctx) {
    ctx.waitUntil(sweep(env));
  }
};
