const crypto = require('crypto');
const User = require('../models/User');
const RevokedToken = require('../models/RevokedToken');
const tokenService = require('../services/tokenService');
const { AppError, catchAsync } = require('../utils/errorUtils');
const rateLimit = require('express-rate-limit');
const logger = require('../config/logger');

// ── Protect route ────────────────────────────────────────────────────────────
exports.protect = catchAsync(async (req, res, next) => {
  // 1. Token extract
  let token;
  if (req.headers.authorization?.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) {
    return next(new AppError('You are not logged in.', 401));
  }

  // 2. JWT signature verify
  let decoded;
  try {
    decoded = tokenService.verifyAccessToken(token);
  } catch (err) {
    return next(new AppError('Invalid or expired token. Please login again.', 401));
  }

  // 3. Token blacklist check (specific token revoked?)
  //    jti না থাকলে token hash use করো
  const jti = decoded.jti || crypto.createHash('sha256').update(token).digest('hex').slice(0, 32);
  const isBlacklisted = await RevokedToken.findOne({ jti }).lean();
  if (isBlacklisted) {
    return next(new AppError('Session has been revoked. Please login again.', 401));
  }

  // 4. User DB check
  const user = await User.findById(decoded.userId).select(
    '+passwordChangedAt +tokenRevokedAt'
  );
  if (!user) {
    return next(new AppError('User no longer exists.', 401));
  }

  // 5. Account active check
  if (!user.isActive) {
    return next(new AppError('Account has been deactivated.', 401));
  }

  // 6. Password changed after token issued?
  if (user.changedPasswordAfter(decoded.iat)) {
    return next(new AppError('Password was recently changed. Please login again.', 401));
  }

  // 7. ★ FORCE LOGOUT CHECK ★
  //    logout_all / revoke device / admin ban করলে tokenRevokedAt set হয়
  //    Token এর iat সেই timestamp এর আগে হলে → block
  if (user.tokenRevokedAt) {
    const revokedAt = Math.floor(user.tokenRevokedAt.getTime() / 1000);
    if (decoded.iat < revokedAt) {
      return next(new AppError('You have been logged out remotely. Please login again.', 401));
    }
  }

  req.user = user;
  next();
});

// ── Role-based authorization ──────────────────────────────────────────────────
exports.authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return next(new AppError('You do not have permission to perform this action.', 403));
  }
  next();
};

// ── Tenant middleware ─────────────────────────────────────────────────────────
exports.requireTenant = catchAsync(async (req, res, next) => {
  const tenantId = req.headers['x-tenant-id'];
  if (!tenantId) return next(new AppError('Tenant ID required.', 400));

  const userTenant = req.user.tenants?.find(t => t.tenantId === tenantId);
  if (!userTenant) return next(new AppError('Access denied to this tenant.', 403));

  req.tenant = userTenant;
  next();
});

// ── Rate limiters ─────────────────────────────────────────────────────────────
exports.loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.body.email || req.ip,
});

exports.registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'Too many registrations. Try again in 1 hour.' },
});

exports.passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { success: false, message: 'Too many reset requests. Try again in 1 hour.' },
  keyGenerator: (req) => req.body.email || req.ip,
});

exports.apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, message: 'Too many requests. Please slow down.' },
});
