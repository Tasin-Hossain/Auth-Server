const mongoose = require('mongoose');

// Token blacklist — revoke করা access token গুলো এখানে রাখা হয়
// TTL index দিয়ে automatically expire হয়ে যাবে (token এর expiry অনুযায়ী)
const revokedTokenSchema = new mongoose.Schema({
  jti: { 
    type: String, 
    required: true, 
    unique: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  reason: {
    type: String,
    enum: ['logout', 'logout_all', 'session_revoked', 'device_removed', 'password_changed', 'security'],
    default: 'logout'
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 } // MongoDB TTL — automatically delete হবে
  }
}, { 
  timestamps: false,
  versionKey: false
});

module.exports = mongoose.model('RevokedToken', revokedTokenSchema);
