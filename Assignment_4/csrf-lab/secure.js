// SECURE: CSRF token (synchronizer token pattern) + SameSite cookie.
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

let userEmail = 'pulu@example.com';
const sessions = {}; // sessionId -> csrfToken (server-side store, simple demo)

app.use((req, res, next) => {
  let sid = req.cookies.session;
  if (!sid || !sessions[sid]) {
    sid = crypto.randomUUID();
    sessions[sid] = crypto.randomBytes(32).toString('hex'); // token tied to session
    // SameSite=Strict/Lax stops the cookie being sent on cross-site requests
    res.cookie('session', sid, { httpOnly: true, sameSite: 'strict' });
  }
  req.sid = sid;
  next();
});

app.get('/', (req, res) => {
  const token = sessions[req.sid];
  res.send(`
    <!doctype html>
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Account Settings</title>
        <style>
          :root { color-scheme: light; font-family: Arial, sans-serif; color: #1f2933; background: #f4f6f8; }
          * { box-sizing: border-box; }
          body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; }
          main { width: min(100%, 420px); padding: 32px; background: #fff; border: 1px solid #d9e0e6; border-radius: 8px; box-shadow: 0 8px 24px rgba(31, 41, 51, .06); }
          .eyebrow { margin: 0 0 8px; color: #19704a; font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
          h1 { margin: 0 0 24px; font-size: 24px; line-height: 1.2; }
          .status { margin: 0 0 24px; padding: 12px 14px; background: #f8fafb; border: 1px solid #e5e9ed; border-radius: 5px; font-size: 14px; }
          label { display: block; margin-bottom: 8px; font-size: 13px; font-weight: 700; }
          input:not([type="hidden"]) { width: 100%; padding: 11px 12px; border: 1px solid #b8c2cc; border-radius: 5px; font: inherit; color: inherit; }
          input:focus { outline: 2px solid #9ec5fe; outline-offset: 1px; border-color: #3973b9; }
          button { width: 100%; margin-top: 16px; padding: 11px 14px; border: 0; border-radius: 5px; background: #1f2933; color: #fff; font: inherit; font-weight: 700; cursor: pointer; }
          button:hover { background: #364452; }
          .refresh { display: block; margin-top: 20px; color: #52606d; font-size: 13px; text-align: center; }
          a { color: inherit; }
        </style>
      </head>
      <body>
        <main>
          <p class="eyebrow">CSRF lab / secure</p>
          <h1>Account settings</h1>
          <p class="status">Current email: <b>${userEmail}</b></p>
          <form method="POST" action="/change-email">
            <label for="email">Email address</label>
            <input id="email" name="email" type="email" value="${userEmail}">
            <input type="hidden" name="csrf_token" value="${token}">
            <button type="submit">Update email</button>
          </form>
          <a class="refresh" href="/">Refresh</a>
        </main>
      </body>
    </html>
  `);
});

app.post('/change-email', (req, res) => {
  const expected = sessions[req.sid];
  const submitted = req.body.csrf_token;
  // Constant-time compare to avoid timing side channels
  const ok = expected && submitted &&
    crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(submitted.padEnd(expected.length)));
  if (!ok || submitted.length !== expected.length) {
    return res.status(403).send(`
      <!doctype html>
      <html>
        <head>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Request Blocked</title>
          <style>
            :root { color-scheme: light; font-family: Arial, sans-serif; color: #1f2933; background: #f4f6f8; }
            * { box-sizing: border-box; }
            body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; }
            main { width: min(100%, 420px); padding: 32px; background: #fff; border: 1px solid #d9e0e6; border-radius: 8px; box-shadow: 0 8px 24px rgba(31, 41, 51, .06); }
            .eyebrow { margin: 0 0 8px; color: #19704a; font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
            h1 { margin: 0 0 16px; font-size: 24px; line-height: 1.2; }
            .status { margin: 0 0 24px; padding: 12px 14px; background: #f8fafb; border: 1px solid #e5e9ed; border-radius: 5px; font-size: 14px; }
            a { color: #52606d; font-size: 13px; }
          </style>
        </head>
        <body>
          <main>
            <p class="eyebrow">CSRF lab / secure</p>
            <h1>Request blocked</h1>
            <p class="status">Missing or invalid CSRF token.</p>
            <a href="/">Back to account settings</a>
          </main>
        </body>
      </html>
    `);
  }
  userEmail = req.body.email;
  res.send(`
    <!doctype html>
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Email Updated</title>
        <style>
          :root { color-scheme: light; font-family: Arial, sans-serif; color: #1f2933; background: #f4f6f8; }
          * { box-sizing: border-box; }
          body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; }
          main { width: min(100%, 420px); padding: 32px; background: #fff; border: 1px solid #d9e0e6; border-radius: 8px; box-shadow: 0 8px 24px rgba(31, 41, 51, .06); }
          .eyebrow { margin: 0 0 8px; color: #19704a; font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
          h1 { margin: 0 0 16px; font-size: 24px; line-height: 1.2; }
          .status { margin: 0 0 24px; padding: 12px 14px; background: #f8fafb; border: 1px solid #e5e9ed; border-radius: 5px; font-size: 14px; }
          a { color: #52606d; font-size: 13px; }
        </style>
      </head>
      <body>
        <main>
          <p class="eyebrow">CSRF lab / secure</p>
          <h1>Email updated</h1>
          <p class="status">Current email: <b>${userEmail}</b></p>
          <a href="/">Back to account settings</a>
        </main>
      </body>
    </html>
  `);
});

app.listen(4001, () => console.log('SECURE app on http://localhost:4001'));
