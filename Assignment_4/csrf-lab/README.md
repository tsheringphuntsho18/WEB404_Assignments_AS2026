# CSRF Lab

Two account-settings apps that let a user change their email:
- `vulnerable.js` (port 4000): no CSRF protection.
- `secure.js` (port 4001): per-session CSRF token + SameSite cookie.
- `attacker/evil.html`: a page that auto-submits a forged request to the vulnerable app.

## Run
```bash
npm install
node vulnerable.js   # http://localhost:4000
node secure.js       # http://localhost:4001
```

## Demo the attack (vulnerable app)
1. Open http://localhost:4000 in your browser (this "logs you in").
2. Open `attacker/evil.html` directly in the same browser (double-click it, or serve it on another port).
3. It silently submits a form to http://localhost:4000/change-email.
4. Refresh http://localhost:4000 — the email has changed to attacker@evil.com, with no action from you beyond opening the page.

## Demo the fix (secure app)
1. Open http://localhost:4001 — the form now includes a hidden `csrf_token` field.
2. Try submitting a request without it (or from `evil.html` pointed at port 4001) — rejected with HTTP 403.
3. Submit the real form on the page — token matches the session, request succeeds.
