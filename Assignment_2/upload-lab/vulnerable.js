// VULNERABLE: no validation. For demonstration only (run on localhost).
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const dir = path.join(__dirname, 'public', 'uploads'); // inside web root
fs.mkdirSync(dir, { recursive: true });

// Keeps the original filename and accepts any type or size
const upload = multer({
  storage: multer.diskStorage({
    destination: dir,
    filename: (req, file, cb) => cb(null, file.originalname),
  }),
});

app.use(express.static(path.join(__dirname, 'public'))); // uploads served directly

app.post('/upload', upload.single('file'), (req, res) => {
  res.send(`Uploaded: <a href="/uploads/${req.file.originalname}">${req.file.originalname}</a>`);
});

app.listen(3000, () => console.log('VULNERABLE app on http://localhost:3000'));
