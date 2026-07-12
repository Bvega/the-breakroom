'use strict';
const express = require('express');
const { protect } = require('../middleware/auth');
const {
  register,
  verifyMagicLink,
  requestWorkVerification,
  verifyOTP,
  getMe
} = require('../controllers/authController');

const router = express.Router();

// POST /api/v1/auth/register
// Body: { email, displayName }
router.post('/register', register);

// GET /api/v1/auth/verify-magic/:token
router.get('/verify-magic/:token', verifyMagicLink);

// POST /api/v1/auth/verify-work   (protected — user must be logged in)
// Body: { workEmail }
// PRIVACY: workEmail is ephemeral; never stored raw — only its hash + domain persist
router.post('/verify-work', protect, requestWorkVerification);

// POST /api/v1/auth/verify-otp   (protected)
// Body: { workEmailHash, otp }
router.post('/verify-otp', protect, verifyOTP);

// GET /api/v1/auth/me   (protected)
// PRIVACY: response never includes email fields
router.get('/me', protect, getMe);

module.exports = router;
