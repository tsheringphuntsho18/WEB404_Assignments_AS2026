# JWT Auth Lab

One server, two modes: **Vulnerable** and **Secure**, same login/me/admin flow.

## Run
```bash
npm install
node server.js      # http://localhost:5000
```
- `http://localhost:5000/vulnerable`
- `http://localhost:5000/secure`

Demo login: username `pulu`, password `password123` (role `user`). There is no `admin`
account — the point of the attacks is to reach the admin endpoint without one.

## Using the page
1. Log in with the demo credentials. The token appears in the text box.
2. "Call /me" shows your decoded claims. "Call /admin" should return 403 (you're `role: user`).
3. "Forge alg:none admin token" builds a token with no signature client-side and loads it into
   the box — click "Call /admin" to try it.

## Attack 1: alg:none bypass
Click "Forge alg:none admin token" on the **Vulnerable** tab, then "Call /admin" — it succeeds.
Try the same on the **Secure** tab — it is rejected (`jwt signature is required`).

## Attack 2: weak-secret brute force + forged token
```bash
node attacks/brute_force.js "<paste a token from the Vulnerable tab>"
```
This checks the token's signature against `attacks/wordlist.txt`, recovers the secret
(`jwt123`), and prints a brand-new forged admin token signed with it. Paste that token into
the page and call `/admin` on the Vulnerable tab — it succeeds. The same forged token fails
on the Secure tab (different, random 256-bit secret).

## Attack 3: expired tokens still accepted
Vulnerable tokens expire in 10 seconds, but the server never checks `exp`. Log in, wait more
than 10 seconds, then "Call /me" with the same token — it still works. Secure tokens expire
in 15 seconds and are properly rejected (`jwt expired`) after that.

## Control: naive tampering without resigning
Hand-editing a token's payload (e.g. changing `role` to `admin`) without recomputing the
signature is rejected by **both** modes, because the HS256 signature check itself is intact.
This isolates exactly what each real attack above is exploiting (the `none` algorithm, or the
weak secret) rather than "no signature check at all".

## Fixes in the Secure mode
- Fixed algorithm allow-list (`algorithms: ['HS256']`) — `alg: none` and algorithm-confusion
  attacks are rejected outright.
- Strong, random 256-bit secret, generated at server startup — not brute-forceable.
- Short expiry enforced by the `jsonwebtoken` library itself (`TokenExpiredError`).
- Generic error messages; role comes only from the server-side user store at login time.
