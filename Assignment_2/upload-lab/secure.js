// SECURE: layered upload defences.
const express = require('express');
const multer = require('multer');
const FileType = require('file-type');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const UPLOAD_DIR = path.join(__dirname, 'private_uploads'); // outside web root
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const MAX_SIZE = 2 * 1024 * 1024; // 2 MB
// Allowlist: extension -> expected real MIME type
const ALLOWED = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.pdf': 'application/pdf' };

const upload = multer({
  storage: multer.memoryStorage(),            // nothing touches disk until validated
  limits: { fileSize: MAX_SIZE, files: 1 },   // size and count limits
  fileFilter: (req, file, cb) => {
    const name = path.basename(file.originalname).toLowerCase();
    const ext = path.extname(name);
    // 1. extension allowlist, 2. block double extensions like shell.php.jpg
    if (!ALLOWED[ext]) return cb(new Error('Extension not allowed'));
    if (name.split('.').length > 2) return cb(new Error('Multiple extensions not allowed'));
    // 3. client-declared MIME must match
    if (file.mimetype !== ALLOWED[ext]) return cb(new Error('MIME type mismatch'));
    cb(null, true);
  },
});

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

app.post('/upload', (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) return res.status(400).send(`Rejected: ${err.message}`);
    if (!req.file) return res.status(400).send('Rejected: no file');

    // 4. magic-byte check: real content must match the extension
    const detected = await FileType.fromBuffer(req.file.buffer);
    const ext = path.extname(req.file.originalname).toLowerCase();
    if (!detected || detected.mime !== ALLOWED[ext]) {
      return res.status(400).send('Rejected: file content does not match its type');
    }

    // 5. random server-side name, extension from detected type (never user input)
    const id = crypto.randomUUID() + '.' + detected.ext;
    fs.writeFileSync(path.join(UPLOAD_DIR, id), req.file.buffer, { mode: 0o640 });
    res.send(`Uploaded. File ID: ${id}  (download at /files/${id})`);
  });
});

// 6. controlled download: no execution, forced download, no MIME sniffing
app.get('/files/:id', (req, res) => {
  const id = path.basename(req.params.id);
  if (!/^[0-9a-f-]{36}\.(jpg|png|pdf)$/.test(id)) return res.sendStatus(404);
  const file = path.join(UPLOAD_DIR, id);
  if (!fs.existsSync(file)) return res.sendStatus(404);
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Content-Disposition': 'attachment',
    'Content-Security-Policy': "default-src 'none'",
  });
  res.sendFile(file);
});

app.listen(3001, () => console.log('SECURE app on http://localhost:3001'));
