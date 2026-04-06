const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const deviceSchema = new mongoose.Schema({
  deviceId: { type: String, required: true },
  deviceName: String,
  browser: String,
  os: String,
  ip: String,
  location: String,
  lastUsed: { type: Date, default: Date.now },
  isTrusted: { type: Boolean, default: false },
  userAgent: String
}, { _id: false });

const loginHistorySchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  ip: String,
  location: String,
  browser: String,
  os: String,
  deviceId: String,
  success: Boolean,
  failReason: String,
  riskScore: { type: Number, default: 0 }
}, { _id: true });

const backupCodeSchema = new mongoose.Schema({
  code: String,
  used: { type: Boolean, default: false },
  usedAt: Date
}, { _id: false });

const tenantSchema = new mongoose.Schema({
  tenantId: String,
  role: { type: String, default: 'member' },
  joinedAt: { type: Date, default: Date.now }
}, { _id: false });

const userSchema = new mongoose.Schema({
  // Basic Info
  firstName: { type: String, required: true, trim: true, maxlength: 50 },
  lastName: { type: String, required: true, trim: true, maxlength: 50 },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Invalid email format']
  },
  password: { 
    type: String, 
    minlength: 8,
    select: false 
  },
  avatar: { type: String, default: '' },
  
  // Account Status
  isEmailVerified: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  isLocked: { type: Boolean, default: false },
  lockUntil: Date,
  role: { type: String, enum: ['user', 'admin', 'super_admin'], default: 'user' },
  
  // OAuth / SSO
  ssoProvider: { type: String, enum: ['local', 'google', 'github', 'microsoft'], default: 'local' },
  ssoId: String,
  
  // Multi-tenant
  tenants: [tenantSchema],
  currentTenant: String,
  
  // Email Verification
  emailVerificationToken: String,
  emailVerificationExpire: Date,
  
  // Password Reset
  passwordResetToken: String,
  passwordResetExpire: Date,
  passwordChangedAt: Date,
  // Force-logout timestamp — protect middleware checks this against token iat
  tokenRevokedAt: Date,
  passwordHistory: [{ hash: String, changedAt: Date }],
  
  // 2FA
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String, select: false },
  twoFactorBackupCodes: { type: [backupCodeSchema], select: false },
  twoFactorVerifiedAt: Date,
  
  // Devices & Sessions
  devices: [deviceSchema],
  activeRefreshTokens: [{ 
    token: String, 
    deviceId: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date
  }],
  
  // Security & Audit
  loginHistory: [loginHistorySchema],
  failedLoginAttempts: { type: Number, default: 0 },
  lastFailedLogin: Date,
  lastLogin: Date,
  lastIp: String,
  
  // Risk & Fraud
  riskScore: { type: Number, default: 0 },
  isSuspicious: { type: Boolean, default: false },
  suspiciousFlags: [String],
  fraudAlerts: [{ 
    type: String, 
    description: String, 
    timestamp: { type: Date, default: Date.now },
    resolved: { type: Boolean, default: false }
  }],

  // Profile
  phone: String,
  timezone: { type: String, default: 'UTC' },
  language: { type: String, default: 'en' },
  
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes (email already indexed via unique:true in schema definition)
// userSchema.index({ email: 1 }); -- removed duplicate
userSchema.index({ emailVerificationToken: 1 });
userSchema.index({ passwordResetToken: 1 });
userSchema.index({ ssoProvider: 1, ssoId: 1 });
userSchema.index({ 'tenants.tenantId': 1 });

// Virtual: fullName
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual: isLockExpired
userSchema.virtual('isLockExpired').get(function() {
  return this.lockUntil && this.lockUntil < Date.now();
});

// Pre-save: hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  // Save to history (keep last 5)
  if (this.password) {
    this.passwordHistory = this.passwordHistory || [];
    this.passwordHistory.unshift({ hash: this.password, changedAt: new Date() });
    if (this.passwordHistory.length > 5) this.passwordHistory = this.passwordHistory.slice(0, 5);
  }
  
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordChangedAt = new Date();
  next();
});

// Method: compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Method: check if password was changed after JWT issued
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Method: generate email verification token
userSchema.methods.generateEmailVerificationToken = function() {
  const token = crypto.randomBytes(32).toString('hex');
  this.emailVerificationToken = crypto.createHash('sha256').update(token).digest('hex');
  this.emailVerificationExpire = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  return token;
};

// Method: generate password reset token
userSchema.methods.generatePasswordResetToken = function() {
  const token = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(token).digest('hex');
  this.passwordResetExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
  return token;
};

// Method: increment failed login
userSchema.methods.incrementFailedLogin = async function() {
  this.failedLoginAttempts += 1;
  this.lastFailedLogin = new Date();
  
  if (this.failedLoginAttempts >= 5) {
    this.isLocked = true;
    this.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
  }
  await this.save({ validateBeforeSave: false });
};

// Method: reset failed login
userSchema.methods.resetFailedLogin = async function() {
  this.failedLoginAttempts = 0;
  this.isLocked = false;
  this.lockUntil = undefined;
  await this.save({ validateBeforeSave: false });
};

// Method: add login history
userSchema.methods.addLoginHistory = async function(data) {
  this.loginHistory.unshift(data);
  if (this.loginHistory.length > 50) {
    this.loginHistory = this.loginHistory.slice(0, 50);
  }
  await this.save({ validateBeforeSave: false });
};

// Method: check password was used before
userSchema.methods.isPasswordUsedBefore = async function(newPassword) {
  for (const old of this.passwordHistory || []) {
    if (await bcrypt.compare(newPassword, old.hash)) return true;
  }
  return false;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
