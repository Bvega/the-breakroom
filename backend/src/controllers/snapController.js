'use strict';
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sharp = require('sharp');

// ─── Ensure uploads directory exists ─────────────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, '..', '..', 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /api/v1/snaps/upload
 * Accepts a single image (multipart/form-data, field "image").
 *
 * Processing pipeline:
 *  1. Validate file presence
 *  2. Resize to max 1200px width (keep aspect ratio)
 *  3. Convert to webp @ quality 80
 *  4. Strip ALL metadata (EXIF, GPS, ICC)
 *  5. Save with a randomised UUID filename
 *
 * PRIVACY: Phase 4 — the original filename is NEVER used or stored.
 */
const uploadImage = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No image file provided' });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // PRIVACY GATE — Phase 4 requirement
    // sharp strips ALL metadata (EXIF, GPS, ICC, XMP) by default when
    // .withMetadata() is NOT called.  Do NOT add .withMetadata() here.
    // This ensures no geolocation, camera info, or author data leaks.
    // ──────────────────────────────────────────────────────────────────────────
    const processed = await sharp(req.file.buffer)
      .resize({ width: 1200, withoutEnlargement: true })
      .webp({ quality: 80 })
      .toBuffer();

    // Generate a randomised UUID filename — never expose the original filename
    const filename = `${crypto.randomUUID()}.webp`;
    const filepath = path.join(UPLOADS_DIR, filename);

    await fs.promises.writeFile(filepath, processed);

    return res.status(201).json({
      success: true,
      imageUrl: `/uploads/${filename}`
    });
  } catch (err) {
    console.error('[uploadImage]', err.message);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
};

module.exports = { uploadImage };
