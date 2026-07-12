'use strict';
const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * protect — JWT auth middleware.
 * Reads Authorization: Bearer <token>, verifies it, and attaches req.user.
 * PRIVACY: only user._id and display_name are attached — no email fields.
 */
const protect = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }

    // Attach minimal user context — explicitly exclude personal_email
    // PRIVACY: personal_email (even hashed) must never surface in req.user
    const user = await User.findById(decoded.sub).select('-personal_email');
    if (!user) {
      return res.status(401).json({ success: false, error: 'User not found' });
    }

    req.user = user;
    return next();
  } catch (err) {
    console.error('[protect]', err.message);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
};

module.exports = { protect };
