# Assignment: JWT-Based Authentication, Common Attacks, and Secure Handling

**Student:** Tshering Phuntsho  
**Student ID:** 02230310  
**Module:** WEB404 - Secure Coding Practices     
**Date:** 21 October, 2026 

## 1. Objective

To build a JWT-based authentication system with a simple frontend, demonstrate common JWT attacks against a deliberately weak implementation and then implement and verify secure JWT handling that resists the same attacks.

## 2. Introduction

A JSON Web Token (JWT) is a signed, self-contained token used to prove a user's identity and claims (such as a role) on each request, without the server needing to look up a session on every call. The token has three parts: a header (declares the algorithm), a payload (the claims) and a signature. The server is supposed to verify the signature using a secret or key it controls. JWTs are only as secure as how they are issued and verified: common implementation mistakes include trusting the algorithm declared inside the token, using a weak or guessable signing secret and failing to enforce token expiry.

## 3. Tools and Environment

| Item | Details |
| --- | --- |
| Operating system | Linux |
| Runtime | Node.js |
| Framework | Express 4 |
| JWT library (secure mode only) | jsonwebtoken |
| Testing tools | Browser, curl, Postman, a small offline brute-force script |

One server, two modes, selectable by tab in a simple frontend:

- **Vulnerable mode** (`/vulnerable`): custom, deliberately weak token signing and verification.
- **Secure mode** (`/secure`): proper use of the `jsonwebtoken` library with explicit algorithm restriction, a strong secret, and enforced expiry.

Both modes share one demo account (`pulu` / `password123`, role `user`). No `admin` account exists — the attacks aim to reach the `/admin` endpoint without ever having admin credentials, which is the realistic goal of privilege escalation via a token flaw.

**Command:** ` tree -I node_modules`.

![image](screenshots/s1.png)
*Screenshot 1: Project files.*

## 4. System Design

| Endpoint | Purpose |
| --- | --- |
| `POST /<mode>/login` | Checks username/password, issues a token with `username` and `role` claims |
| `GET /<mode>/me` | Requires a bearer token, returns the decoded claims |
| `GET /<mode>/admin` | Requires a bearer token with `role: admin`, returns a secret flag message |

The frontend (one shared page for both modes) provides a login form, a text box holding the current token (editable, so a forged or tampered token can be pasted in), buttons to call `/me` and `/admin`, and a button that forges an `alg: none` token directly in the browser for the first attack.

![image](screenshots/s2.png)
*Screenshot 2: The login page in the browser, Vulnerable tab.*

## 5. Vulnerable Implementation

Three deliberate weaknesses were built into the vulnerable mode's token handling:

```javascript
const WEAK_SECRET = 'jwt123'; // short, dictionary-guessable

function vulnVerify(token) {
  const parts = token.split('.');
  const header = JSON.parse(b64urlDecode(parts[0]));
  const payload = JSON.parse(b64urlDecode(parts[1]));
  if (header.alg === 'none') return payload;              // (1) trusts alg from the token itself
  const expected = hmac(parts[0] + '.' + parts[1], WEAK_SECRET);
  if (expected !== parts[2]) throw new Error('Bad signature');
  return payload;                                           // (3) "exp" is never checked
}
```

1. If the token's header says `"alg": "none"`, the signature check is skipped entirely. This mirrors a real, historical class of JWT library bugs where the algorithm is read from attacker-controlled input instead of being fixed by the server.
2. The signing secret (`jwt123`) is short and appears in common password/secret wordlists.
3. The `exp` (expiry) claim is included in issued tokens but is never checked during verification, so expired tokens remain valid indefinitely.

![image](screenshots/s3.png)
*Screenshot 3: `server.js`, the `vulnVerify` function.*

## 6. Attacks Performed

### 6.1 Attack 1: Algorithm (`alg: none`) Bypass

**Steps:**

1. Log in normally on the Vulnerable tab as `pulu` (role `user`).
2. Click **Call /admin** — rejected with `403 Forbidden: admin role required`, as expected.

![image](screenshots/s4.png)
*Screenshot 4: User role forbidden.*

3. Click **Forge alg:none admin token**. The page builds, entirely client-side, a token with header `{"alg":"none"}` and payload `{"username":"attacker","role":"admin"}`, with an empty signature.
4. Click **Call /admin** again with this forged token.

**Result:** the server returns `200 OK` with `{"message":"Welcome, admin! Secret admin data: 1234-ADMIN-FLAG"}` — full privilege escalation with no valid credentials and no signature at all.

![image](screenshots/s5.png)
*Screenshot 5: The forged token in the box and the successful admin response.*

Equivalent command-line proof:

```bash
curl -s localhost:5000/vulnerable/admin \
  -H "Authorization: Bearer eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VybmFtZSI6ICJhdHRhY2tlciIsICJyb2xlIjogImFkbWluIn0."
```
![image](screenshots/s6.png)
*Screenshot 6: Terminal output of the command above.*

### 6.2 Attack 2: Weak-Secret Brute Force and Forgery

**Steps:**

1. Log in on the Vulnerable tab and copy the issued token.
2. Run the offline cracking script against it:

```bash
node attacks/brute_force.js "<copied token>"
```

The script recomputes the HMAC-SHA256 signature of the token's header and payload using every word in `attacks/wordlist.txt` and compares it to the token's actual signature.

**Result:** the script recovers the secret `jwt123` and prints a brand-new, freely chosen, correctly signed token:

```
Secret recovered: jwt123
Forged admin token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImF0dGFja2VyIiwicm9sZSI6ImFkbWluIn0...
```

3. Paste the forged token into the page and click **Call /admin**.

**Result:** `200 OK`, admin data returned, again with no real credentials — this time via a properly signed token, because the attacker now holds the same secret the server uses.

![image](screenshots/s7.png)
*Screenshot 7: Terminal output of the brute-force script finding the secret and printing the forged token.*

![image](screenshots/s8.png)
*Screenshot 8: The forged token used on the page, with the successful admin response.*

### 6.3 Attack 3: Expired Tokens Still Accepted

**Steps:**

1. Log in on the Vulnerable tab (token expiry is set to 10 seconds for this demo).
2. Wait more than 10 seconds.
3. Click **Call /me** with the same, now-expired token.

**Result:** the request still succeeds and returns the user's claims, because `vulnVerify` never checks `exp`.

![image](screenshots/s9.png)
*Screenshot 9: The response after waiting, showing the expired token still accepted.*

### 6.4 Control: Naive Tampering Without Resigning

To confirm exactly what the above attacks exploit (and not simply "no signature check"), a legitimate token's payload was hand-edited (`role` changed to `admin`) while keeping the original signature unchanged, and submitted to the **same vulnerable** `/admin` endpoint.

**Result:** rejected with `401 Invalid token: Bad signature`. This shows the HS256 signature check is genuinely present and working for ordinary tokens; the real attacks above succeed specifically because of the `alg: none` trust issue and the weak secret, not because signatures are ignored altogether.

![image](screenshots/s10.png)
*Screenshot 10: The tampered-but-not-resigned token being rejected.*

## 7. Results Summary

| # | Attack / Test | Vulnerable mode | Secure mode |
| --- | --- | --- | --- |
| 1 | `alg: none` forged admin token | Accepted, admin data returned | Rejected: `jwt signature is required` |
| 2 | Weak-secret brute force + forged, resigned admin token | Accepted, admin data returned | Rejected: `invalid signature` |
| 3 | Expired token reused | Accepted after expiry | Rejected: `jwt expired` |
| 4 (control) | Tampered payload, original signature kept | Rejected: `Bad signature` | Rejected: `Bad signature` |

## 8. Secure Implementation

The secure mode addresses each weakness directly, using the well-tested `jsonwebtoken` library instead of hand-rolled signing/verification:

```javascript
const SECURE_SECRET = crypto.randomBytes(32).toString('hex'); // strong, random, 256-bit

function secureSign(payload) {
  return jwt.sign(payload, SECURE_SECRET, { algorithm: 'HS256', expiresIn: '15s' });
}
function secureVerify(token) {
  return jwt.verify(token, SECURE_SECRET, { algorithms: ['HS256'] }); // fixed allow-list
}
```

| Weakness exploited | Fix applied |
| --- | --- |
| Server trusted the `alg` field from the token | `algorithms: ['HS256']` is passed explicitly to `jwt.verify`; any other algorithm, including `none`, is rejected before signature checking even happens |
| Weak, dictionary-guessable secret | A random 256-bit secret is generated at server startup; in production this would come from an environment variable or secret manager, not be regenerated per run |
| Expiry never checked | `jsonwebtoken` enforces `exp` automatically and throws `TokenExpiredError`, turned into a `401` response |
| Role taken from client-controlled payload | Role is looked up from the server-side user store only at login time and embedded in a token the server itself signs; a client can never set its own role |

![image](screenshots/s11.png)
*Screenshot 11: `server.js`, the secure `secureSign`/`secureVerify` functions.*

## 9. Testing the Secure Version

All three attacks from Section 6 were repeated against the Secure tab's endpoints, using the same forged tokens where applicable:

```bash
# Attack 1 repeated
curl -s localhost:5000/secure/admin -H "Authorization: Bearer <alg-none-token>"
# -> 401 {"error":"Invalid token: jwt signature is required"}

# Attack 2 repeated
curl -s localhost:5000/secure/admin -H "Authorization: Bearer <resigned-with-jwt123-token>"
# -> 401 {"error":"Invalid token: invalid signature"}

# Attack 3 repeated (wait >15s after login first)
curl -s localhost:5000/secure/me -H "Authorization: Bearer <expired-secure-token>"
# -> 401 {"error":"Invalid token: jwt expired"}
```
![image](screenshots/s12.png)
*Screenshot 12: Terminal output of the three commands above, all returning 401*

A legitimate login and `/me` call on the Secure tab, within the token's validity window, still succeeds normally, confirming the fixes do not break the intended functionality.

![image](screenshots/s13.png)
*Screenshot 13: Successful login and `/me` call on the Secure tab.*

## 10. Analysis

All three vulnerable-mode attacks share a common root cause: the server did not fully control the terms of its own trust decision. Accepting `alg: none` let the attacker decide not to be checked at all; a weak secret let the attacker reconstruct the one piece of server-side trust (the signing key) offline, with no interaction with the server and no rate limiting possible; and skipping `exp` meant a token's validity period, once issued, was purely decorative. In each case the fix was to make the server, not the token, the sole authority over how it verifies trust: a fixed algorithm list, a secret large enough to resist offline search, and a verification library that correctly enforces the claims it understands.

## 11. Limitations and Further Improvements

- Token expiry was shortened to 10/15 seconds purely so the "expired token" attack could be demonstrated quickly; a real system would use minutes-to-hours for access tokens.
- Tokens are stored in a JavaScript variable/text box on the page for demo convenience; in a real application, storing tokens in an `HttpOnly`, `Secure` cookie reduces exposure to theft via XSS, at the cost of needing CSRF protection for cookie-based auth (see the CSRF assignment).
- No refresh-token or revocation mechanism is implemented; a compromised secure-mode token is still valid until it naturally expires. Production systems typically pair short-lived access tokens with a revocable refresh token.
- The secure secret is regenerated on every server restart, which would invalidate all outstanding tokens; a real deployment would load a fixed secret from an environment variable or secret manager.
- RS256 (asymmetric signing) is a further option for systems where multiple services must verify tokens without being trusted to issue them, since only the private key issuer can sign, while any holder of the public key can verify.

## 12. Conclusion

The vulnerable JWT implementation allowed full privilege escalation to an admin role through three independent issues: trusting an attacker-controlled algorithm field, using a brute-forceable signing secret, and never enforcing token expiry. Each attack was demonstrated end-to-end, from the browser and from the command line, and a control test confirmed that ordinary payload tampering was already blocked, isolating exactly what each exploit relied on. Rebuilding token issuance and verification with the `jsonwebtoken` library, an explicit algorithm allow-list, a strong random secret, and enforced expiry blocked every attack while preserving normal login behaviour. The exercise shows that JWT security depends entirely on how a server issues and verifies tokens, not on the JWT format itself.

## 13. References

- RFC 7519: JSON Web Token (JWT)
- OWASP JSON Web Token Cheat Sheet
- Auth0: Critical Vulnerabilities in JSON Web Token Libraries (the "alg: none" and algorithm-confusion attack classes)
- jsonwebtoken (npm) documentation
