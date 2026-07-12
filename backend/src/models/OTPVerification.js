'use strict';
const mongoose = require('mongoose');
const crypto = require('crypto');

const otpVerificationSchema = new mongoose.Schema({
  _id: {
    type: mongoose.Schema.Types.UUID,
    default: () => crypto.randomUUID()
  },
  // PRIVACY: work_email_hash is a SHA-256 digest of the work email.
  // The raw work email is NEVER stored — only this hash persists so we can
  // match the OTP submission without retaining the plaintext address.
  work_email_hash: {
    type: String,
    required: true,
    index: true
  },
  otp_code: {
    type: String,
    required: true
  },
  // PRIVACY: company_domain_id links this OTP to a company without revealing the inbox address
  company_domain_id: {
    type: mongoose.Schema.Types.UUID,
    ref: 'Company',
    required: true
  },
  // PRIVACY: user_id ties this OTP request to an authenticated user session
  user_id: {
    type: mongoose.Schema.Types.UUID,
    ref: 'User',
    required: true
  },
  expires_at: {
    type: Date,
    required: true,
    default: () => new Date(Date.now() + 15 * 60 * 1000) // 15 minutes from now
  },
  used: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

// TTL index: MongoDB will automatically delete expired OTP documents
otpVerificationSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('OTPVerification', otpVerificationSchema);
