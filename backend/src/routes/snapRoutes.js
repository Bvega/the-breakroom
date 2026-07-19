'use strict';
const express = require('express');
const multer = require('multer');
const { protect } = require('../middleware/auth');
const upload = require('../config/upload');
const { uploadImage } = require('../controllers/snapController');

const router = express.Router();

// POST /api/v1/snaps/upload   (protected — user must be logged in)
// Accepts: multipart/form-data with field "image"
router.post('/upload', protect, upload.single('image'), uploadImage);

// ─── Multer error handler ────────────────────────────────────────────────────
// Catches MulterError (file too large, unexpected field) and custom file-filter
// rejections, returning a consistent { success, error } 400 response.
// eslint-disable-next-line no-unused-vars
router.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    // Multer-specific errors (e.g. LIMIT_FILE_SIZE, LIMIT_UNEXPECTED_FILE)
    const messages = {
      LIMIT_FILE_SIZE: 'File too large. Maximum size is 5 MB',
      LIMIT_UNEXPECTED_FILE: 'Unexpected field. Use "image" as the form field name'
    };
    return res.status(400).json({
      success: false,
      error: messages[err.code] || err.message
    });
  }

  if (err.code === 'INVALID_FILE_TYPE') {
    return res.status(400).json({ success: false, error: err.message });
  }

  // Unknown error — let Express default handler deal with it
  console.error('[snapRoutes]', err.message);
  return res.status(500).json({ success: false, error: 'Server error' });
});

module.exports = router;
