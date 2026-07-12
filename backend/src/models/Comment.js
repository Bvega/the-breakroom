const mongoose = require('mongoose');
const crypto = require('crypto');

const commentSchema = new mongoose.Schema({
  _id: {
    type: mongoose.Schema.Types.UUID,
    default: () => crypto.randomUUID()
  },
  // PRIVACY: comment_id uniquely identifies this comment
  comment_id: {
    type: mongoose.Schema.Types.UUID,
    default: function() { return this._id; },
    unique: true,
    required: true
  },
  snap_id: {
    type: mongoose.Schema.Types.UUID,
    ref: 'CultureSnap',
    required: true
  },
  // PRIVACY: user_id links this comment to the author (User.user_id)
  user_id: {
    type: mongoose.Schema.Types.UUID,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: true,
    maxlength: 200
  },
  type: {
    type: String,
    enum: ['comment', 'suggestion'],
    required: true
  },
  // PRIVACY: is_anonymous determines whether the user's identity is concealed on this comment
  is_anonymous: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

module.exports = mongoose.model('Comment', commentSchema);
