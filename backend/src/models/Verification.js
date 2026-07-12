const mongoose = require('mongoose');
const crypto = require('crypto');

const verificationSchema = new mongoose.Schema({
  _id: {
    type: mongoose.Schema.Types.UUID,
    default: () => crypto.randomUUID()
  },
  // PRIVACY: verification_id uniquely identifies this verification record
  verification_id: {
    type: mongoose.Schema.Types.UUID,
    default: function() { return this._id; },
    unique: true,
    required: true
  },
  // PRIVACY: user_id links this verification record to the user identity (User.user_id)
  user_id: {
    type: mongoose.Schema.Types.UUID,
    ref: 'User',
    required: true
  },
  // PRIVACY: company_domain_id links this verification record to the corporate entity (Company.company_domain_id)
  company_domain_id: {
    type: mongoose.Schema.Types.UUID,
    ref: 'Company',
    required: true
  },
  verified_at: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

module.exports = mongoose.model('Verification', verificationSchema);
