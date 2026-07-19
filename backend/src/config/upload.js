'use strict';
const multer = require('multer');

// ─── Multer configuration (Phase 4 — Media Upload) ─────────────────────────

const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

/**
 * File filter — reject anything that isn't jpeg, png, or webp.
 * Passes a custom error so the route-level error handler can return 400.
 */
const fileFilter = (_req, file, cb) => {
  if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
    return cb(null, true);
  }
  const err = new Error('Only jpeg, png, and webp images are allowed');
  err.code = 'INVALID_FILE_TYPE';
  return cb(err, false);
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter
});

module.exports = upload;
