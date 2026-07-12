const mongoose = require('mongoose');
const crypto = require('crypto');

// Helper function to hash emails
const hashEmail = (email) => {
  if (!email) return email;
  return crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex');
};

const userSchema = new mongoose.Schema({
  _id: {
    type: mongoose.Schema.Types.UUID,
    default: () => crypto.randomUUID()
  },
  // PRIVACY: user_id is the primary identifier for tracking user actions without using raw email
  user_id: {
    type: mongoose.Schema.Types.UUID,
    default: function() { return this._id; },
    unique: true,
    required: true
  },
  // PRIVACY: personal_email is stored exclusively as a SHA-256 hash to protect user identity
  personal_email: {
    type: String,
    unique: true,
    required: true
  },
  // PRIVACY: display_name is the public-facing moniker for the user's profile
  display_name: {
    type: String,
    required: true
  },
  avatar_url: {
    type: String
  }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

// Pre-save middleware to automatically hash personal_email
userSchema.pre('save', function() {
  if (this.isModified('personal_email')) {
    this.personal_email = hashEmail(this.personal_email);
  }
});

// Static helper to query users by their raw email
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ personal_email: hashEmail(email) });
};

module.exports = mongoose.model('User', userSchema);
