const mongoose = require('mongoose');

const tenantSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  slug: { type: String, required: true, unique: true, lowercase: true },
  domain: String,
  logo: String,
  plan: { type: String, enum: ['free', 'pro', 'enterprise'], default: 'free' },
  isActive: { type: Boolean, default: true },
  settings: {
    allowRegistration: { type: Boolean, default: true },
    require2FA: { type: Boolean, default: false },
    sessionTimeout: { type: Number, default: 60 }, // minutes
    allowedDomains: [String],
    ssoEnabled: { type: Boolean, default: false },
    ssoConfig: {
      provider: String,
      clientId: String,
      clientSecret: String,
      callbackUrl: String
    }
  },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  members: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    role: { type: String, enum: ['owner', 'admin', 'member'], default: 'member' },
    joinedAt: { type: Date, default: Date.now }
  }],
  maxMembers: { type: Number, default: 5 },
}, { timestamps: true });

tenantSchema.index({ slug: 1 });
tenantSchema.index({ domain: 1 });

module.exports = mongoose.model('Tenant', tenantSchema);
