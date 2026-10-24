// JWT auth demo: one server, two modes (Vulnerable / Secure), tabbed UI.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static(__dirname + '/public'));

// Demo user store. Only "pulu" can log in; "admin" exists only as a role
// an attacker should NOT be able to reach without the real credentials.
const USERS = { pulu: { password: 'password123', role: 'user' } };

// ============== VULNERABLE MODE ==============
// Deliberately weak secret: short, dictionary-guessable, realistic mistake.
const WEAK_SECRET = 'jwt123';

function b64url(input) {
  return Buffer.from(typeof input === 'string' ? input : JSON.stringify(input))
    .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString();
}
function hmac(data, secret) {
  return crypto.createHmac('sha256', secret).update(data).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function vulnSign(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = { ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 10 }; // 10s
  const data = b64url(header) + '.' + b64url(body);
  return data + '.' + hmac(data, WEAK_SECRET);
}

// VULNERABILITY 1: trusts the "alg" field from the token itself; "none" skips
// signature verification entirely (a real, historical JWT library bug class).
// VULNERABILITY 2: weak, short, dictionary-guessable secret for HS256.
// VULNERABILITY 3: never checks "exp", so expired tokens still work.
function vulnVerify(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  const header = JSON.parse(b64urlDecode(parts[0]));
  const payload = JSON.parse(b64urlDecode(parts[1]));
  if (header.alg === 'none') return payload;                 // (1) no signature check at all
  const expected = hmac(parts[0] + '.' + parts[1], WEAK_SECRET);
  if (expected !== parts[2]) throw new Error('Bad signature');
  return payload;                                              // (3) exp never checked
}

app.post('/vulnerable/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS[username];
  if (!u || u.password !== password) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: vulnSign({ username, role: u.role }) });
});

function vulnAuth(req, res, next) {
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    req.user = vulnVerify(token);
    next();
  } catch (e) { res.status(401).json({ error: 'Invalid token: ' + e.message }); }
}

app.get('/vulnerable/me', vulnAuth, (req, res) => res.json({ user: req.user }));
app.get('/vulnerable/admin', vulnAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden: admin role required' });
  res.json({ message: 'Welcome, admin! Secret admin data: 1234-ADMIN-FLAG' });
});

// ============== SECURE MODE ==============
// Strong random secret, generated at startup (use an env var / secret manager in production).
const SECURE_SECRET = crypto.randomBytes(32).toString('hex');

function secureSign(payload) {
  return jwt.sign(payload, SECURE_SECRET, { algorithm: 'HS256', expiresIn: '15s' });
}
// FIX 1: algorithms explicitly allow-listed, so "alg: none" / algorithm-confusion is rejected.
// FIX 2: strong 256-bit random secret, not brute-forceable in practice.
// FIX 3: jwt.verify enforces "exp" and throws TokenExpiredError automatically.
function secureVerify(token) {
  return jwt.verify(token, SECURE_SECRET, { algorithms: ['HS256'] });
}

app.post('/secure/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS[username];
  if (!u || u.password !== password) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: secureSign({ username, role: u.role }) });
});

function secureAuth(req, res, next) {
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    req.user = secureVerify(token);
    next();
  } catch (e) { res.status(401).json({ error: 'Invalid token: ' + e.message }); }
}

app.get('/secure/me', secureAuth, (req, res) => res.json({ user: req.user }));
app.get('/secure/admin', secureAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden: admin role required' });
  res.json({ message: 'Welcome, admin! Secret admin data: 1234-ADMIN-FLAG' });
});

app.get('/', (req, res) => res.redirect('/vulnerable'));
app.get('/vulnerable', (req, res) => res.sendFile(__dirname + '/public/index.html'));
app.get('/secure', (req, res) => res.sendFile(__dirname + '/public/index.html'));

app.listen(5000, () => console.log('JWT demo (both modes) on http://localhost:5000'));
