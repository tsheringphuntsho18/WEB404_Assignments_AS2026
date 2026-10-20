# Secure File Upload Lab

Two apps, same form:
- `vulnerable.js` (port 3000): no validation, files stored in web root.
- `secure.js` (port 3001): layered defences.

## Run
```bash
npm install
node vulnerable.js     # http://localhost:3000
node secure.js         # http://localhost:3001
```

## Test files
```bash
mkdir t && cd t
echo '<?php system($_GET["c"]); ?>' > shell.php
cp shell.php fake.jpg              # PHP code disguised as .jpg
cp shell.php shell.php.jpg         # double extension
echo '<script>alert(1)</script>' > xss.html
head -c 3000000 /dev/zero > big.png
```

## Attacks
```bash
# Vulnerable: upload and then execute/read from web root
curl -F "file=@shell.php" localhost:3000/upload
curl localhost:3000/uploads/shell.php
curl -F "file=@xss.html" localhost:3000/upload      # stored XSS when opened

# Secure: all of these should be rejected
curl -F "file=@shell.php"                      localhost:3001/upload
curl -F "file=@fake.jpg;type=image/jpeg"       localhost:3001/upload
curl -F "file=@shell.php.jpg;type=image/jpeg"  localhost:3001/upload
curl -F "file=@xss.html"                       localhost:3001/upload
curl -F "file=@big.png;type=image/png"         localhost:3001/upload
# A genuine PNG/JPG/PDF is accepted
```

## Security measures in secure.js
1. Extension allowlist (jpg, jpeg, png, pdf)
2. Double-extension block (`shell.php.jpg`)
3. Client MIME type must match extension
4. Magic-byte check (real content must match type) using `file-type`
5. File size (2 MB) and file count limits
6. Random UUID filename, extension from detected type (no user-controlled names or paths)
7. Stored outside web root, never executed
8. Download route with ID regex, `Content-Disposition: attachment`, `nosniff`, restrictive CSP
