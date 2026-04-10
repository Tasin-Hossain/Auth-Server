const crypto = require('crypto');
const UAParser = require('ua-parser-js');
const geoip = require('geoip-lite');
const { v4: uuidv4 } = require('uuid');

const User = require('../models/User');
const tokenBlacklistService = require('../services/tokenBlacklistService');
const tokenService = require('../services/tokenService');
const emailService = require('../services/emailService');
const fraudDetectionService = require('../services/fraudDetectionService');
const { AppError, catchAsync } = require('../utils/errorUtils');
const logger = require('../config/logger');

// Parse device info from request
const parseDeviceInfo = (req) => {
  const ua = UAParser(req.headers['user-agent'] || '');
  // trust proxy=1 এর পরে req.ip সঠিক real IP দেবে
  const ip = req.ip || '0.0.0.0';
  const geo = geoip.lookup(ip.replace('::ffff:', ''));
  const location = geo
    ? [geo.city, geo.country].filter(Boolean).join(', ') || 'Unknown'
    : 'Unknown';

  // x-device-id header থেকে নাও, না থাকলে নতুন বানাও
  const deviceId = req.headers['x-device-id'] || uuidv4();

  return {
    ip,
    location,
    browser: [ua.browser.name, ua.browser.major].filter(Boolean).join(' ') || 'Unknown',
    os: [ua.os.name, ua.os.version].filter(Boolean).join(' ') || 'Unknown',
    userAgent: req.headers['user-agent'] || '',
    deviceId,
  };
};

// @desc  Register
// @route POST /api/v1/auth/register
exports.register = catchAsync(async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;

  const exists = await User.findOne({ email });
  if (exists) return next(new AppError('Email already registered', 400));

  const regRisk = await fraudDetectionService.analyzeRegistrationRisk({ email });
  if (regRisk.shouldBlock) return next(new AppError('Registration blocked for security reasons', 403));

  const user = await User.create({ firstName, lastName, email, password, ssoProvider: 'local' });

  const verifyToken = user.generateEmailVerificationToken();
  await user.save({ validateBeforeSave: false });

  try {
    await emailService.sendVerificationEmail(user, verifyToken);
  } catch (err) {
    user.emailVerificationToken = undefined;
    user.emailVerificationExpire = undefined;
    await user.save({ validateBeforeSave: false });
    logger.error('Verification email failed:', err);
  }

  res.status(201).json({
    success: true,
    message: 'Registration successful! Please verify your email.',
    data: { user: { id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName } }
  });
});

// @desc  Login
// @route POST /api/v1/auth/login
exports.login = catchAsync(async (req, res, next) => {
  const { email, password, totpCode, trustDevice } = req.body;
  const deviceInfo = parseDeviceInfo(req);

  if (!email || !password) return next(new AppError('Please provide email and password', 400));

  const user = await User.findOne({ email })
    .select('+password +twoFactorSecret +twoFactorBackupCodes');

  if (!user) return next(new AppError('Invalid email or password', 401));

  // Account lock check
  if (user.isLocked && user.lockUntil > Date.now()) {
    const mins = Math.ceil((user.lockUntil - Date.now()) / 60000);
    return next(new AppError(`Account locked. Try again in ${mins} minutes`, 423));
  }
  if (user.isLocked && user.lockUntil <= Date.now()) {
    await user.resetFailedLogin();
  }

  if (!user.isEmailVerified) return next(new AppError('Please verify your email first', 401));
  if (!user.isActive) return next(new AppError('Account deactivated', 401));

  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    await user.incrementFailedLogin();
    await user.addLoginHistory({ ...deviceInfo, success: false, failReason: 'wrong_password' });
    return next(new AppError('Invalid email or password', 401));
  }

  // Fraud analysis
  const isKnownDevice = user.devices?.some(d => d.deviceId === deviceInfo.deviceId);
  const fraud = await fraudDetectionService.analyzeLoginRisk(user, { ...deviceInfo, isKnownDevice });

  if (fraud.shouldBlock) {
    await user.addLoginHistory({ ...deviceInfo, success: false, failReason: 'fraud_blocked', riskScore: fraud.riskScore });
    return next(new AppError('Login blocked for security reasons. Contact support.', 403));
  }

  // 2FA check
  if (user.twoFactorEnabled) {
    if (!totpCode) {
      // tempToken এ deviceInfo সব কিছু রাখো — verify2FA তে লাগবে
      const tempToken = tokenService.generateAccessToken({
        userId:    user._id.toString(),
        requires2FA: true,
        // device tracking এর জন্য
        deviceId:  deviceInfo.deviceId,
        ip:        deviceInfo.ip,
        location:  deviceInfo.location,
        browser:   deviceInfo.browser,
        os:        deviceInfo.os,
        userAgent: deviceInfo.userAgent,
        // fraud score
        riskScore: fraud.riskScore,
        riskLevel: fraud.riskLevel,
        riskFlags: fraud.flags,
        isKnownDevice,
        trustDevice: trustDevice === true,
      });
      return res.status(200).json({ success: true, requires2FA: true, tempToken });
    }

    const speakeasy = require('speakeasy');
    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret, encoding: 'base32', token: totpCode, window: 2
    });

    if (!isValid) {
      const backup = user.twoFactorBackupCodes?.find(bc => !bc.used && bc.code === totpCode);
      if (!backup) return next(new AppError('Invalid 2FA code', 401));
      backup.used = true;
      backup.usedAt = new Date();
      await user.save({ validateBeforeSave: false });
    }
  }

  await user.resetFailedLogin();

  // Device management
  const existingDevice = user.devices?.find(d => d.deviceId === deviceInfo.deviceId);
  const isNewDevice = !existingDevice;

  if (existingDevice) {
    existingDevice.lastUsed = new Date();
    existingDevice.ip = deviceInfo.ip;
    existingDevice.location = deviceInfo.location;
  } else {
    user.devices = user.devices || [];
    user.devices.push({
      deviceId: deviceInfo.deviceId,
      deviceName: `${deviceInfo.browser} on ${deviceInfo.os}`,
      browser: deviceInfo.browser,
      os: deviceInfo.os,
      ip: deviceInfo.ip,
      location: deviceInfo.location,
      userAgent: deviceInfo.userAgent,
      isTrusted: trustDevice === true,
    });
    if (user.devices.length > 10) user.devices = user.devices.slice(-10);
  }

  user.lastLogin = new Date();
  user.lastIp = deviceInfo.ip;

  // Risk score update on user
  user.riskScore = fraud.riskScore;
  if (fraud.shouldAlert) {
    user.isSuspicious = true;
    user.suspiciousFlags = [...new Set([...(user.suspiciousFlags || []), ...fraud.flags])];
  }

  await user.addLoginHistory({ ...deviceInfo, success: true, riskScore: fraud.riskScore });

  // Tokens
  const tokenPayload = { userId: user._id.toString(), email: user.email, role: user.role, deviceId: deviceInfo.deviceId };
  const { accessToken, refreshToken } = tokenService.generateTokenPair(tokenPayload);

  const hashedRT = crypto.createHash('sha256').update(refreshToken).digest('hex');
  user.activeRefreshTokens = (user.activeRefreshTokens || []).filter(t => t.expiresAt > new Date());
  user.activeRefreshTokens.push({
    token: hashedRT,
    deviceId: deviceInfo.deviceId,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
  if (user.activeRefreshTokens.length > 5) user.activeRefreshTokens = user.activeRefreshTokens.slice(-5);

  await user.save({ validateBeforeSave: false });

  tokenService.setRefreshTokenCookie(res, refreshToken);

  // Alerts
  if (isNewDevice && (user.loginHistory?.length || 0) > 1) {
    emailService.sendNewDeviceAlert(user, deviceInfo).catch(e => logger.error('New device alert failed:', e));
  }
  if (fraud.shouldAlert) {
    emailService.sendSuspiciousActivityAlert(user, { type: 'Suspicious login', ...deviceInfo }).catch(e => logger.error('Suspicious alert failed:', e));
  }

  res.status(200).json({
    success: true,
    message: 'Login successful',
    data: {
      accessToken,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        avatar: user.avatar,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
        lastLogin: user.lastLogin,
      },
      security: { riskScore: fraud.riskScore, riskLevel: fraud.riskLevel, isNewDevice },
    },
  });
});

// @desc  Refresh Token
// @route POST /api/v1/auth/refresh
exports.refreshToken = catchAsync(async (req, res, next) => {
  const token = req.cookies.refreshToken;
  if (!token) return next(new AppError('No refresh token', 401));

  let decoded;
  try { decoded = tokenService.verifyRefreshToken(token); }
  catch { tokenService.clearRefreshTokenCookie(res); return next(new AppError('Invalid refresh token', 401)); }

  const user = await User.findById(decoded.userId);
  if (!user || !user.isActive) return next(new AppError('User not found', 401));

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const stored = user.activeRefreshTokens?.find(t => t.token === hashedToken);
  if (!stored || stored.expiresAt < new Date()) {
    tokenService.clearRefreshTokenCookie(res);
    return next(new AppError('Refresh token expired or revoked', 401));
  }

  const tokenPayload = { userId: user._id.toString(), email: user.email, role: user.role, deviceId: decoded.deviceId };
  const { accessToken, refreshToken: newRT } = tokenService.generateTokenPair(tokenPayload);

  user.activeRefreshTokens = user.activeRefreshTokens.filter(t => t.token !== hashedToken);
  user.activeRefreshTokens.push({
    token: crypto.createHash('sha256').update(newRT).digest('hex'),
    deviceId: decoded.deviceId,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
  await user.save({ validateBeforeSave: false });
  tokenService.setRefreshTokenCookie(res, newRT);

  res.status(200).json({ success: true, data: { accessToken } });
});

// @desc  Logout current device
// @route POST /api/v1/auth/logout
exports.logout = catchAsync(async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;
  const accessToken = req.headers.authorization?.split(' ')[1];

  if (accessToken) await tokenBlacklistService.revokeAccessToken(accessToken, req.user.id, 'logout');

  if (refreshToken) {
    const hashed = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await User.findByIdAndUpdate(req.user.id, { $pull: { activeRefreshTokens: { token: hashed } } });
  }

  tokenService.clearRefreshTokenCookie(res);
  res.status(200).json({ success: true, message: 'Logged out successfully' });
});

// @desc  Logout all devices
// @route POST /api/v1/auth/logout-all
exports.logoutAll = catchAsync(async (req, res, next) => {
  await User.findByIdAndUpdate(req.user.id, {
    $set: { activeRefreshTokens: [], tokenRevokedAt: new Date() }
  });
  tokenService.clearRefreshTokenCookie(res);
  res.status(200).json({ success: true, message: 'Logged out from all devices' });
});

// @desc  Verify Email
// @route GET /api/v1/auth/verify-email/:token
exports.verifyEmail = catchAsync(async (req, res, next) => {
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const user = await User.findOne({ emailVerificationToken: hashedToken, emailVerificationExpire: { $gt: Date.now() } });
  if (!user) return next(new AppError('Invalid or expired token', 400));

  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpire = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({ success: true, message: 'Email verified! You can now login.' });
});

// @desc  Resend verification
// @route POST /api/v1/auth/resend-verification
exports.resendVerification = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return next(new AppError('No account found with this email', 404));
  if (user.isEmailVerified) return next(new AppError('Email already verified', 400));

  const token = user.generateEmailVerificationToken();
  await user.save({ validateBeforeSave: false });
  await emailService.sendVerificationEmail(user, token);

  res.status(200).json({ success: true, message: 'Verification email sent!' });
});

// @desc  Forgot Password
// @route POST /api/v1/auth/forgot-password
exports.forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(200).json({ success: true, message: 'If an account exists, a reset link was sent.' });
  }

  const token = user.generatePasswordResetToken();
  await user.save({ validateBeforeSave: false });

  try {
    await emailService.sendPasswordResetEmail(user, token);
    res.status(200).json({ success: true, message: 'Password reset email sent!' });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpire = undefined;
    await user.save({ validateBeforeSave: false });
    return next(new AppError('Email could not be sent', 500));
  }
});

// @desc  Reset Password
// @route POST /api/v1/auth/reset-password/:token
exports.resetPassword = catchAsync(async (req, res, next) => {
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetExpire: { $gt: Date.now() } }).select('+password');
  if (!user) return next(new AppError('Invalid or expired token', 400));

  const { password, confirmPassword } = req.body;
  if (password !== confirmPassword) return next(new AppError('Passwords do not match', 400));

  const usedBefore = await user.isPasswordUsedBefore(password);
  if (usedBefore) return next(new AppError('Cannot reuse a previous password', 400));

  user.password = password;
  user.passwordResetToken = undefined;
  user.passwordResetExpire = undefined;
  user.activeRefreshTokens = [];
  user.tokenRevokedAt = new Date();
  await user.save();

  tokenService.clearRefreshTokenCookie(res);
  res.status(200).json({ success: true, message: 'Password reset! Please login.' });
});

// @desc  Change Password
// @route POST /api/v1/auth/change-password
exports.changePassword = catchAsync(async (req, res, next) => {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;
  if (newPassword !== confirmNewPassword) return next(new AppError('Passwords do not match', 400));

  const user = await User.findById(req.user.id).select('+password');
  if (!await user.comparePassword(currentPassword)) return next(new AppError('Current password incorrect', 401));

  const usedBefore = await user.isPasswordUsedBefore(newPassword);
  if (usedBefore) return next(new AppError('Cannot reuse a previous password', 400));

  user.password = newPassword;
  user.activeRefreshTokens = [];
  user.tokenRevokedAt = new Date();
  await user.save();

  tokenService.clearRefreshTokenCookie(res);
  res.status(200).json({ success: true, message: 'Password changed! Please login again.' });
});

// @desc  Get current user
// @route GET /api/v1/auth/me
exports.getMe = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  res.status(200).json({ success: true, data: { user } });
});
