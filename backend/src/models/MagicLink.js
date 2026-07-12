'use strict';
const mongoose = require('mongoose');
const crypto = require('crypto');

const magicLinkSchema = new mongoose.Schema({
  _id: {
    type: mongoose.Schema.Types.UUID,
    default: () => crypto.randomUUID()
  },
  // Raw hex token (64 chars) — stored here so we can look it up on verify.
  // Only the token's existence is sensitive; the email is never stored on this record.
  token: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  // PRIVACY: user_id links this magic link to a user account without storing any email
  user_id: {
    type: mongoose.Schema.Types.UUID,
    ref: 'User',
    required: true
  },
  expires_at: {
    type: Date,
    required: true,
    default: () => new Date(Date.now() + 60 * 60 * 1000) // 1 hour from now
  },
  used: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

// TTL index: MongoDB will auto-delete expired magic links
magicLinkSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('MagicLink', magicLinkSchema);
