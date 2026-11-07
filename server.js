// Life Match Christian — server
// Owner: Prince Bush, Founder & Owner. Blue Christian dating app, worldwide.
// Stack: Node (Express) + Postgres. Deploy on Render: Starter web ($7/mo)
// + Basic Postgres ($6/mo) = about $13/mo. See README.md.
// Security notes: PINs are SHA-256 hashed (salted with SESSION_SECRET).
// Owner Console is protected by OWNER_PASSCODE (set it in Render env vars;
// never commit it). Users must be 18+. Every profile starts "pending" and
// is hidden until Prince approves it in the Owner Console.
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'life-match-christian-dev-secret';
const OWNER_PASSCODE = process.env.OWNER_PASSCODE || '';
if (!OWNER_PASSCODE) console.warn('WARNING: OWNER_PASSCODE is not set. Set it in Render env vars before launch.');

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Database ----------
const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

async function initDb() {
  if (!pool) { console.warn('No DATABASE_URL — running without a database (local preview only).'); return; }
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
  console.log('Database ready.');
}
const q = (text, params) => pool.query(text, params);

// ---------- Tokens (simple signed tokens; no extra dependency) ----------
function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyToken(token) {
  try {
    const [body, sig] = String(token || '').split('.');
    const expect = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig || ''), Buffer.from(expect))) return null;
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch { return null; }
}
function hashPin(pin) { return crypto.createHash('sha256').update(SESSION_SECRET + ':' + pin).digest('hex'); }
const publicUser = (u) => u && { id: u.id, name: u.name, age: u.age, gender: u.gender, country: u.country, city: u.city, church: u.church, faith_story: u.faith_story, photo_url: u.photo_url, status: u.status, created_at: u.created_at };

async function auth(req, res, next) {
  const data = verifyToken((req.headers.authorization || '').replace(/^Bearer /, ''));
  if (!data || data.role !== 'user') return res.status(401).json({ error: 'Please sign in.' });
  const { rows } = await q('SELECT * FROM users WHERE id=$1', [data.id]);
  if (!rows[0] || rows[0].status === 'blocked') return res.status(401).json({ error: 'Account not available.' });
  req.user = rows[0]; next();
}
function ownerAuth(req, res, next) {
  const data = verifyToken((req.headers.authorization || '').replace(/^Bearer /, ''));
  if (!data || data.role !== 'owner') return res.status(401).json({ error: 'Owner only.' });
  next();
}
const needDb = (req, res, next) => pool ? next() : res.status(503).json({ error: 'Database is not connected yet. Set DATABASE_URL on Render.' });

// ---------- Auth: email + PIN ----------
app.post('/api/auth/signup', needDb, async (req, res) => {
  try {
    const { email, pin, name, age, gender, looking_for, country, city, church, faith_story, photo_url } = req.body;
    if (!email || !pin || !name || !age || !gender || !country) return res.status(400).json({ error: 'Email, PIN, name, age, gender and country are required.' });
    if (String(pin).length < 4) return res.status(400).json({ error: 'PIN must be at least 4 numbers.' });
    if (Number(age) < 18) return res.status(400).json({ error: 'You must be 18 or older to join.' });
    const { rows } = await q(
      `INSERT INTO users (email, pin_hash, name, age, gender, looking_for, country, city, church, faith_story, photo_url, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending') RETURNING *`,
      [String(email).toLowerCase().trim(), hashPin(String(pin)), name, Number(age), gender, looking_for || 'everyone', country, city || '', church || '', faith_story || '', photo_url || '']);
    res.json({ token: signToken({ role: 'user', id: rows[0].id }), user: publicUser(rows[0]), message: 'Welcome! Your profile is waiting for Prince to approve it. You will see Discover after approval.' });
  } catch (e) { res.status(400).json({ error: e.code === '23505' ? 'That email already has an account. Please sign in.' : 'Could not create your account.' }); }
});
app.post('/api/auth/login', needDb, async (req, res) => {
  const { email, pin } = req.body;
  const { rows } = await q('SELECT * FROM users WHERE email=$1', [String(email || '').toLowerCase().trim()]);
  if (!rows[0] || rows[0].pin_hash !== hashPin(String(pin || ''))) return res.status(401).json({ error: 'Email or PIN is wrong.' });
  res.json({ token: signToken({ role: 'user', id: rows[0].id }), user: publicUser(rows[0]) });
});
app.get('/api/me', needDb, auth, (req, res) => res.json({ user: publicUser(req.user) }));

// ---------- Discover / Like / Match ----------
app.get('/api/discover', needDb, auth, async (req, res) => {
  if (req.user.status !== 'approved') return res.json({ waiting: true, profiles: [] });
  const { country, min_age, max_age, search } = req.query;
  const params = [req.user.id]; let where = `status='approved' AND id <> $1 AND id NOT IN (SELECT target_id FROM likes WHERE liker_id=$1)`;
  if (req.user.looking_for && req.user.looking_for !== 'everyone') { params.push(req.user.looking_for); where += ` AND gender=$${params.length}`; }
  if (country) { params.push(country); where += ` AND country ILIKE $${params.length}`; }
  if (min_age) { params.push(Number(min_age)); where += ` AND age >= $${params.length}`; }
  if (max_age) { params.push(Number(max_age)); where += ` AND age <= $${params.length}`; }
  if (search) { params.push(`%${search}%`); where += ` AND (name ILIKE $${params.length} OR city ILIKE $${params.length} OR church ILIKE $${params.length})`; }
  const { rows } = await q(`SELECT * FROM users WHERE ${where} ORDER BY created_at DESC LIMIT 50`, params);
  res.json({ waiting: false, profiles: rows.map(publicUser) });
});
app.post('/api/like', needDb, auth, async (req, res) => {
  const { target_id, liked } = req.body;
  if (!target_id || Number(target_id) === req.user.id) return res.status(400).json({ error: 'Choose another profile.' });
  await q(`INSERT INTO likes (liker_id, target_id, liked) VALUES ($1,$2,$3)
    ON CONFLICT (liker_id, target_id) DO UPDATE SET liked=EXCLUDED.liked`, [req.user.id, Number(target_id), !!liked]);
  let matched = false;
  if (liked) {
    const { rows } = await q('SELECT 1 FROM likes WHERE liker_id=$1 AND target_id=$2 AND liked=true', [Number(target_id), req.user.id]);
    if (rows.length) {
      const a = Math.min(req.user.id, Number(target_id)), b = Math.max(req.user.id, Number(target_id));
      const m = await q(`INSERT INTO matches (user_a, user_b) VALUES ($1,$2) ON CONFLICT (user_a, user_b) DO NOTHING RETURNING *`, [a, b]);
      matched = true;
      return res.json({ matched, match_id: m.rows[0] ? m.rows[0].id : (await q('SELECT id FROM matches WHERE user_a=$1 AND user_b=$2', [a, b])).rows[0].id });
    }
  }
  res.json({ matched });
});
app.get('/api/matches', needDb, auth, async (req, res) => {
  const { rows } = await q(
    `SELECT m.*, u.id AS other_id, u.name, u.age, u.country, u.city, u.church, u.photo_url,
       (SELECT COUNT(*) FROM messages WHERE match_id=m.id AND sender_id<>$1 AND is_read=false) AS unread
     FROM matches m JOIN users u ON u.id = CASE WHEN m.user_a=$1 THEN m.user_b ELSE m.user_a END
     WHERE m.user_a=$1 OR m.user_b=$1 ORDER BY m.created_at DESC`, [req.user.id]);
  res.json({ matches: rows.map(r => ({ id: r.id, other: publicUser({ id: r.other_id, name: r.name, age: r.age, country: r.country, city: r.city, church: r.church, photo_url: r.photo_url }), unread: Number(r.unread), created_at: r.created_at })) });
});

// ---------- Chat (saved messages, unread, typing, verse/prayer quick messages) ----------
app.get('/api/messages/:matchId', needDb, auth, async (req, res) => {
  const mid = Number(req.params.matchId);
  const ok = await q('SELECT 1 FROM matches WHERE id=$1 AND (user_a=$2 OR user_b=$2)', [mid, req.user.id]);
  if (!ok.rows.length) return res.status(403).json({ error: 'Not your match.' });
  const { rows } = await q('SELECT * FROM messages WHERE match_id=$1 ORDER BY created_at ASC LIMIT 200', [mid]);
  await q('UPDATE messages SET is_read=true WHERE match_id=$1 AND sender_id<>$2', [mid, req.user.id]);
  res.json({ messages: rows });
});
app.post('/api/messages', needDb, auth, async (req, res) => {
  const { match_id, body, kind } = req.body;
  if (!body || !String(body).trim()) return res.status(400).json({ error: 'Write a message first.' });
  const ok = await q('SELECT 1 FROM matches WHERE id=$1 AND (user_a=$2 OR user_b=$2)', [Number(match_id), req.user.id]);
  if (!ok.rows.length) return res.status(403).json({ error: 'Not your match.' });
  const { rows } = await q('INSERT INTO messages (match_id, sender_id, body, kind) VALUES ($1,$2,$3,$4) RETURNING *',
    [Number(match_id), req.user.id, String(body).slice(0, 2000), ['text', 'verse', 'prayer'].includes(kind) ? kind : 'text']);
  res.json({ message: rows[0] });
});
app.post('/api/typing', needDb, auth, async (req, res) => {
  const { match_id, is_typing } = req.body;
  await q(`INSERT INTO typing_states (match_id, user_id, is_typing, updated_at) VALUES ($1,$2,$3,NOW())
    ON CONFLICT (match_id, user_id) DO UPDATE SET is_typing=EXCLUDED.is_typing, updated_at=NOW()`, [Number(match_id), req.user.id, !!is_typing]);
  res.json({ ok: true });
});
app.get('/api/typing/:matchId', needDb, auth, async (req, res) => {
  const { rows } = await q('SELECT is_typing FROM typing_states WHERE match_id=$1 AND user_id<>$2 AND updated_at > NOW() - INTERVAL \'10 seconds\'', [Number(req.params.matchId), req.user.id]);
  res.json({ typing: rows.some(r => r.is_typing) });
});

// ---------- Voice / video calls (WebRTC signalling; media is peer-to-peer) ----------
app.post('/api/calls/signal', needDb, auth, async (req, res) => {
  const { match_id, type, payload } = req.body;
  const ok = await q('SELECT 1 FROM matches WHERE id=$1 AND (user_a=$2 OR user_b=$2)', [Number(match_id), req.user.id]);
  if (!ok.rows.length) return res.status(403).json({ error: 'Not your match.' });
  const { rows } = await q('INSERT INTO call_signals (match_id, sender_id, type, payload) VALUES ($1,$2,$3,$4) RETURNING *',
    [Number(match_id), req.user.id, type, payload || {}]);
  res.json({ signal: rows[0] });
});
app.get('/api/calls/signals/:matchId', needDb, auth, async (req, res) => {
  const since = Number(req.query.since || 0);
  const { rows } = await q('SELECT * FROM call_signals WHERE match_id=$1 AND id>$2 AND sender_id<>$3 ORDER BY created_at ASC LIMIT 50',
    [Number(req.params.matchId), since, req.user.id]);
  res.json({ signals: rows });
});

// ---------- Owner Console (Prince Bush only) ----------
app.post('/api/owner/login', needDb, (req, res) => {
  if (!OWNER_PASSCODE) return res.status(500).json({ error: 'Owner passcode is not set on the server yet.' });
  if (String(req.body.passcode || '') !== OWNER_PASSCODE) return res.status(401).json({ error: 'Wrong owner passcode.' });
  res.json({ token: signToken({ role: 'owner' }) });
});
app.get('/api/owner/pending', needDb, ownerAuth, async (req, res) => {
  const { rows } = await q(`SELECT * FROM users ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, created_at DESC`);
  res.json({ users: rows.map(u => ({ ...publicUser(u), email: u.email })) });
});
app.post('/api/owner/set-status', needDb, ownerAuth, async (req, res) => {
  const { user_id, status } = req.body;
  if (!['approved', 'rejected', 'blocked', 'pending'].includes(status)) return res.status(400).json({ error: 'Bad status.' });
  const { rows } = await q('UPDATE users SET status=$1 WHERE id=$2 RETURNING *', [status, Number(user_id)]);
  if (!rows[0]) return res.status(404).json({ error: 'No such user.' });
  res.json({ user: publicUser(rows[0]) });
});

app.get('/health', (req, res) => res.json({ ok: true, app: 'life-match-christian' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

initDb().then(() => app.listen(PORT, () => console.log(`Life Match Christian running on port ${PORT}`))).catch(e => { console.error(e); process.exit(1); });
