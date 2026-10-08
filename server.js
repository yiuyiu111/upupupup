const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const multer = require('multer');

const app = express();
const port = Number(process.env.PORT) || 3000;
const uploadDir = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'));
const expectedPasswordHash = process.env.UPLOAD_PASSWORD
  ? crypto.createHash('md5').update(process.env.UPLOAD_PASSWORD).digest()
  : null;

fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_request, _file, callback) => callback(null, uploadDir),
  filename: (_request, file, callback) => {
    const extension = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 20);
    callback(null, `${crypto.randomUUID()}${extension}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024, files: 10 },
});

app.post('/api/upload', (request, response) => {
  if (!expectedPasswordHash) {
    return response.status(503).json({ error: 'Upload password is not configured.' });
  }

  const suppliedPasswordHash = crypto.createHash('md5')
    .update(request.get('X-Upload-Password') || '')
    .digest();
  if (!crypto.timingSafeEqual(expectedPasswordHash, suppliedPasswordHash)) {
    return response.status(401).json({ error: 'Invalid upload password.' });
  }

  upload.array('files', 10)(request, response, (error) => {
    if (error) {
      const status = error instanceof multer.MulterError ? 400 : 500;
      return response.status(status).json({ error: error.message || 'Could not save the files.' });
    }

    if (!request.files?.length) {
      return response.status(400).json({ error: 'Choose at least one file to upload.' });
    }

    return response.status(201).json({
      files: request.files.map((file) => ({
        name: file.originalname,
        size: file.size,
        savedAs: file.filename,
      })),
    });
  });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`File upload app listening on port ${port}`);
});
