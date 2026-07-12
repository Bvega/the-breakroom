'use strict';

/**
 * Email configuration module.
 * Phase 3: logs to console only (no real SMTP).
 * Phase 5+: swap these for nodemailer/SES calls.
 */

/**
 * Send a magic link to a personal email address.
 * PRIVACY: personalEmail is a raw personal email — passed straight to the mail transport
 * and never written to the database by this function.
 * @param {string} personalEmail  The recipient's personal email
 * @param {string} token          The raw 64-char magic token
 */
const sendMagicLink = async (personalEmail, token) => {
  const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
  const link = `${baseUrl}/auth/verify-magic/${token}`;

  // PRIVACY: In production this log line must be removed — it exposes the raw email in server logs.
  console.log('\n─────────────────────────────────────────────');
  console.log('[DEV] Magic Link Email');
  console.log(`  To    : ${personalEmail}`);
  console.log(`  Link  : ${link}`);
  console.log('─────────────────────────────────────────────\n');
};

/**
 * Send a 6-digit OTP to a work email address.
 * PRIVACY: workEmail is ephemeral — the caller MUST discard it immediately after
 * this function returns. It is NEVER persisted to any store.
 * @param {string} workEmail  The recipient's work email (ephemeral — discard after call)
 * @param {string} otp        The plaintext 6-digit OTP
 */
const sendOTP = async (workEmail, otp) => {
  // PRIVACY: In production this log line must be removed — it exposes the ephemeral work email.
  console.log('\n─────────────────────────────────────────────');
  console.log('[DEV] OTP Email');
  console.log(`  To    : ${workEmail}`);
  console.log(`  Code  : ${otp}`);
  console.log('  Expires in 15 minutes');
  console.log('─────────────────────────────────────────────\n');
};

module.exports = { sendMagicLink, sendOTP };
