'use strict';
const crypto = require('crypto');

/**
 * Hash an email address with SHA-256.
 * Input is normalized (trimmed + lowercased) before hashing.
 * @param {string} email
 * @returns {string} 64-char hex digest
 */
const hashEmail = (email) => {
  if (!email || typeof email !== 'string') throw new Error('hashEmail: valid email string required');
  return crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex');
};

/**
 * Extract the registrable domain from an email address.
 * The caller MUST discard the raw email immediately after calling this.
 * @param {string} email  e.g. 'jane@mail.eng.stripe.com'
 * @returns {string} e.g. 'stripe.com'
 */
const extractDomain = (email) => {
  if (!email || typeof email !== 'string') throw new Error('extractDomain: valid email string required');
  const parts = email.trim().toLowerCase().split('@');
  if (parts.length !== 2 || !parts[1]) throw new Error('extractDomain: invalid email format');

  const hostParts = parts[1].split('.');
  if (hostParts.length < 2) throw new Error('extractDomain: cannot parse domain');

  // Return only the last two segments (registrable domain)
  return hostParts.slice(-2).join('.');
};

/**
 * Generate a cryptographically secure 6-digit OTP string.
 * @returns {string} e.g. '482913'
 */
const generateOTP = () => {
  // Generate a random integer in [0, 999999] and zero-pad to 6 digits
  const otp = crypto.randomInt(0, 1_000_000);
  return String(otp).padStart(6, '0');
};

/**
 * Generate a cryptographically secure magic-link token.
 * @returns {string} 64-char hex string (32 bytes)
 */
const generateMagicToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

module.exports = { hashEmail, extractDomain, generateOTP, generateMagicToken };
