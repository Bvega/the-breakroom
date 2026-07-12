const mongoose = require('mongoose');
const crypto = require('crypto');

const cultureSnapSchema = new mongoose.Schema({
  _id: {
    type: mongoose.Schema.Types.UUID,
    default: () => crypto.randomUUID()
  },
  // PRIVACY: snap_id uniquely identifies this culture snap
  snap_id: {
    type: mongoose.Schema.Types.UUID,
    default: function() { return this._id; },
    unique: true,
    required: true
  },
  // PRIVACY: user_id links this post to the author (User.user_id)
  user_id: {
    type: mongoose.Schema.Types.UUID,
    ref: 'User',
    required: true
  },
  // PRIVACY: company_domain_id links this post to a specific company context
  company_domain_id: {
    type: mongoose.Schema.Types.UUID,
    ref: 'Company',
    required: true
  },
  image_url: {
    type: String,
    required: true
  },
  caption: {
    type: String,
    required: true,
    maxlength: 280
  },
  // PRIVACY: is_anonymous determines whether the user's identity is concealed on this post
  is_anonymous: {
    type: Boolean,
    default: false
  },
  prompt_id: {
    type: mongoose.Schema.Types.UUID,
    required: true
  },
  like_count: {
    type: Number,
    default: 0
  },
  comment_count: {
    type: Number,
    default: 0
  }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

// Indexes
cultureSnapSchema.index({ company_domain_id: 1 });
cultureSnapSchema.index({ created_at: -1 });

module.exports = mongoose.model('CultureSnap', cultureSnapSchema);
