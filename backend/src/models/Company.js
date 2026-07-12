const mongoose = require('mongoose');
const crypto = require('crypto');

const companySchema = new mongoose.Schema({
  _id: {
    type: mongoose.Schema.Types.UUID,
    default: () => crypto.randomUUID()
  },
  company_domain_id: {
    type: mongoose.Schema.Types.UUID,
    default: function() { return this._id; },
    unique: true,
    required: true
  },
  domain_name: {
    type: String,
    unique: true,
    required: true
  },
  display_name: {
    type: String,
    required: true
  }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

module.exports = mongoose.model('Company', companySchema);
