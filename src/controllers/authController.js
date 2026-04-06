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
const sseService = require('../services/sseService');
const logger = require('../config/logger');

// Helper: parse device info
const parseDeviceInfo = (req) => {
  const ua = UAParser(req.headers['user-agent'] || '');
  const ip = req.ip || req.connection.remoteAddress || '0.0.0.0';
  const geo = geoip.lookup(ip);
  const location = geo ? `${geo.city || ''}, ${geo.country || ''}`.trim().replace(/^,\s*/, '') : 'Unknown';
  
  return {
    ip,
    location,
    browser: `${ua.browser.name || 'Unknown'} ${ua.browser.version || ''}`.trim(),
    os: `${ua.os.name || 'Unknown'} ${ua.os.version || ''}`.trim(),
    userAgent: req.headers['user-agent'] || '',
    deviceId: req.headers['x-device-id'] || uuidv4()
  };
};

// @desc    Register new user
// @route   POST /api/v1/auth/register
exports.register = catchAsync(async (req, res, next) => {
  const { firstName, lastName, email, password, tenantId } = req.body;
  const deviceInfo = parseDeviceInfo(req);

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new AppError('Email already registered', 400));
  }

  // Fraud check on registration
  const regRisk = await fraudDetectionService.analyzeRegistrationRisk({ email, ip: deviceInfo.ip });
  if (regRisk.shouldBlock) {
    return next(new AppError('Registration blocked for security reasons', 403));
  }

  // Create user
  const user = await User.create({
    firstName,
    lastName,
    email,
    password,
    ssoProvider: 'local',
    tenants: tenantId ? [{ tenantId, role: 'member' }] : []
  });

  // Generate email verification token
  const verifyToken = user.generateEmailVerificationToken();
  await user.save({ validateBeforeSave: false });

  // Send verification email
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
    data: {
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isEmailVerified: user.isEmailVerified
      }
    }
  });
});

// @desc    Login user
// @route   POST /api/v1/auth/login
exports.login = catchAsync(async (req, res, next) => {
  const { email, password, totpCode, trustDevice } = req.body;
  const deviceInfo = parseDeviceInfo(req);

  if (!email || !password) {
    return next(new AppError('Please provide email and password', 400));
  }

  // Find user with password
  const user = await User.findOne({ email })
    .select('+password +twoFactorSecret +twoFactorBackupCodes');

  if (!user) {
    return next(new AppError('Invalid email or password', 401));
  }

  // Check account lock
  if (user.isLocked && user.lockUntil > Date.now()) {
    const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
    return next(new AppError(`Account locked. Try again in ${minutesLeft} minutes`, 423));
  }

  // Unlock if lock expired
  if (user.isLocked && user.lockUntil <= Date.now()) {
    await user.resetFailedLogin();
  }

  // Check email verified
  if (!user.isEmailVerified) {
    return next(new AppError('Please verify your email before logging in', 401));
  }

  // Check account active
  if (!user.isActive) {
    return next(new AppError('Account has been deactivated', 401));
  }

  // Verify password
  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    await user.incrementFailedLogin();
    
    // Log failed attempt
    await user.addLoginHistory({
      ...deviceInfo,
      success: false,
      failReason: 'wrong_password'
    });

    return next(new AppError('Invalid email or password', 401));
  }

  // AI Fraud Detection
  const fraudAnalysis = await fraudDetectionService.analyzeLoginRisk(user, {
    ...deviceInfo,
    isKnownDevice: user.devices.some(d => d.deviceId === deviceInfo.deviceId)
  });

  if (fraudAnalysis.shouldBlock) {
    await user.addLoginHistory({
      ...deviceInfo,
      success: false,
      failReason: 'fraud_blocked',
      riskScore: fraudAnalysis.riskScore
    });
    return next(new AppError('Login blocked for security reasons. Please contact support.', 403));
  }

  // Handle 2FA
  if (user.twoFactorEnabled) {
    if (!totpCode) {
      // Return pending 2FA state
      const tempToken = tokenService.generateAccessToken({
        userId: user._id,
        requires2FA: true
      });
      
      return res.status(200).json({
        success: true,
        requires2FA: true,
        tempToken,
        message: 'Please provide your 2FA code'
      });
    }

    // Validate TOTP
    const speakeasy = require('speakeasy');
    const isValidTOTP = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: totpCode,
      window: 2
    });

    // Check backup codes if TOTP fails
    if (!isValidTOTP) {
      const backupCode = user.twoFactorBackupCodes.find(
        bc => !bc.used && bc.code === totpCode
      );
      
      if (!backupCode) {
        return next(new AppError('Invalid 2FA code', 401));
      }
      
      // Mark backup code as used
      backupCode.used = true;
      backupCode.usedAt = new Date();
      await user.save({ validateBeforeSave: false });
    }
  }

  // Reset failed attempts on successful login
  await user.resetFailedLogin();

  // Update device list
  const existingDevice = user.devices.find(d => d.deviceId === deviceInfo.deviceId);
  const isNewDevice = !existingDevice;
  
  if (existingDevice) {
    existingDevice.lastUsed = new Date();
    existingDevice.ip = deviceInfo.ip;
  } else {
    user.devices.push({
      deviceId: deviceInfo.deviceId,
      deviceName: `${deviceInfo.browser} on ${deviceInfo.os}`,
      browser: deviceInfo.browser,
      os: deviceInfo.os,
      ip: deviceInfo.ip,
      location: deviceInfo.location,
      userAgent: deviceInfo.userAgent,
      isTrusted: trustDevice || false
    });
    
    // Keep max 10 devices
    if (user.devices.length > 10) {
      user.devices = user.devices.slice(-10);
    }
  }

  // Update login info
  user.lastLogin = new Date();
  user.lastIp = deviceInfo.ip;

  // Log success
  await user.addLoginHistory({
    ...deviceInfo,
    success: true,
    riskScore: fraudAnalysis.riskScore
  });

  // Generate tokens
  const tokenPayload = {
    userId: user._id.toString(),
    email: user.email,
    role: user.role,
    deviceId: deviceInfo.deviceId
  };

  const { accessToken, refreshToken } = tokenService.generateTokenPair(tokenPayload);

  // Store refresh token
  user.activeRefreshTokens.push({
    token: crypto.createHash('sha256').update(refreshToken).digest('hex'),
    deviceId: deviceInfo.deviceId,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
  });

  // Keep max 5 refresh tokens per user
  if (user.activeRefreshTokens.length > 5) {
    user.activeRefreshTokens = user.activeRefreshTokens.slice(-5);
  }

  await user.save({ validateBeforeSave: false });

  // Set cookie
  tokenService.setRefreshTokenCookie(res, refreshToken);

  // Send new device alert
  if (isNewDevice && user.loginHistory.length > 1) {
    emailService.sendNewDeviceAlert(user, deviceInfo).catch(err => 
      logger.error('New device alert email failed:', err)
    );
  }

  // Send suspicious activity alert
  if (fraudAnalysis.shouldAlert) {
    emailService.sendSuspiciousActivityAlert(user, {
      type: 'Suspicious login attempt',
      ip: deviceInfo.ip,
      location: deviceInfo.location
    }).catch(err => logger.error('Suspicious alert email failed:', err));
    
    user.isSuspicious = true;
    user.suspiciousFlags = [...new Set([...user.suspiciousFlags, ...fraudAnalysis.flags])];
    await user.save({ validateBeforeSave: false });
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
        lastLogin: user.lastLogin
      },
      security: {
        riskScore: fraudAnalysis.riskScore,
        riskLevel: fraudAnalysis.riskLevel,
        isNewDevice
      }
    }
  });
});

// @desc    Refresh access token
// @route   POST /api/v1/auth/refresh
exports.refreshToken = catchAsync(async (req, res, next) => {
  const token = req.cookies.refreshToken;
  
  if (!token) {
    return next(new AppError('No refresh token', 401));
  }

  let decoded;
  try {
    decoded = tokenService.verifyRefreshToken(token);
  } catch (err) {
    tokenService.clearRefreshTokenCookie(res);
    return next(new AppError('Invalid refresh token', 401));
  }

  const user = await User.findById(decoded.userId);
  if (!user || !user.isActive) {
    return next(new AppError('User not found or inactive', 401));
  }

  // Check if refresh token exists in DB
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const storedToken = user.activeRefreshTokens.find(t => t.token === hashedToken);
  
  if (!storedToken || storedToken.expiresAt < new Date()) {
    tokenService.clearRefreshTokenCookie(res);
    return next(new AppError('Refresh token expired or revoked', 401));
  }

  // Generate new token pair (rotation)
  const tokenPayload = {
    userId: user._id.toString(),
    email: user.email,
    role: user.role,
    deviceId: decoded.deviceId
  };

  const { accessToken, refreshToken: newRefreshToken } = tokenService.generateTokenPair(tokenPayload);

  // Replace old refresh token
  user.activeRefreshTokens = user.activeRefreshTokens.filter(t => t.token !== hashedToken);
  user.activeRefreshTokens.push({
    token: crypto.createHash('sha256').update(newRefreshToken).digest('hex'),
    deviceId: decoded.deviceId,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
  });

  await user.save({ validateBeforeSave: false });
  tokenService.setRefreshTokenCookie(res, newRefreshToken);

  res.status(200).json({
    success: true,
    data: { accessToken }
  });
});

// @desc    Logout (current device only)
// @route   POST /api/v1/auth/logout
exports.logout = catchAsync(async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;
  const accessToken  = req.headers.authorization?.split(' ')[1];

  // 1. Blacklist current access token
  if (accessToken) {
    await tokenBlacklistService.revokeAccessToken(accessToken, req.user.id, 'logout');
  }

  // 2. Remove current refresh token from DB
  if (refreshToken) {
    const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await User.findByIdAndUpdate(req.user.id, {
      $pull: { activeRefreshTokens: { token: hashedToken } }
    });
  }

  tokenService.clearRefreshTokenCookie(res);

  res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
});

// @desc    Logout from ALL devices (force-logout every active session)
// @route   POST /api/v1/auth/logout-all
exports.logoutAll = catchAsync(async (req, res, next) => {
  const userId = req.user.id.toString();
  const currentDeviceId = req.headers['x-device-id'];

  // 1. Revoke all sessions in DB
  await User.findByIdAndUpdate(userId, {
    $set: { activeRefreshTokens: [] }
  });

  // 2. SSE → force-logout every OTHER connected device immediately
  sseService.sendToAllDevices(userId, 'force-logout', {
    reason:  'logout_all',
    message: 'You were logged out from all devices.',
  }, currentDeviceId); // exclude current device (it will redirect itself)

  // 3. Clear this device's refresh cookie
  tokenService.clearRefreshTokenCookie(res);

  res.status(200).json({
    success: true,
    message: 'Logged out from all devices successfully',
  });
});

// @desc    Verify email
// @route   GET /api/v1/auth/verify-email/:token
exports.verifyEmail = catchAsync(async (req, res, next) => {
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpire: { $gt: Date.now() }
  });

  if (!user) {
    return next(new AppError('Invalid or expired verification token', 400));
  }

  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpire = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    success: true,
    message: 'Email verified successfully! You can now login.'
  });
});

// @desc    Resend verification email
// @route   POST /api/v1/auth/resend-verification
exports.resendVerification = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new AppError('No account found with this email', 404));
  }

  if (user.isEmailVerified) {
    return next(new AppError('Email is already verified', 400));
  }

  const verifyToken = user.generateEmailVerificationToken();
  await user.save({ validateBeforeSave: false });
  await emailService.sendVerificationEmail(user, verifyToken);

  res.status(200).json({
    success: true,
    message: 'Verification email sent!'
  });
});

// @desc    Forgot password
// @route   POST /api/v1/auth/forgot-password
exports.forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    // Don't reveal if email exists (security best practice)
    return res.status(200).json({
      success: true,
      message: 'If an account exists with that email, a reset link has been sent.'
    });
  }

  const resetToken = user.generatePasswordResetToken();
  await user.save({ validateBeforeSave: false });

  try {
    await emailService.sendPasswordResetEmail(user, resetToken);
    res.status(200).json({
      success: true,
      message: 'Password reset email sent!'
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpire = undefined;
    await user.save({ validateBeforeSave: false });
    return next(new AppError('Email could not be sent', 500));
  }
});

// @desc    Reset password
// @route   POST /api/v1/auth/reset-password/:token
exports.resetPassword = catchAsync(async (req, res, next) => {
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpire: { $gt: Date.now() }
  }).select('+password');

  if (!user) {
    return next(new AppError('Invalid or expired reset token', 400));
  }

  const { password, confirmPassword } = req.body;
  if (password !== confirmPassword) {
    return next(new AppError('Passwords do not match', 400));
  }

  // Check password history
  const isUsedBefore = await user.isPasswordUsedBefore(password);
  if (isUsedBefore) {
    return next(new AppError('Cannot reuse a previous password', 400));
  }

  user.password = password;
  user.passwordResetToken = undefined;
  user.passwordResetExpire = undefined;
  user.activeRefreshTokens = []; // Invalidate all sessions
  await user.save();

  tokenService.clearRefreshTokenCookie(res);

  res.status(200).json({
    success: true,
    message: 'Password reset successful! Please login with your new password.'
  });
});

// @desc    Change password (authenticated)
// @route   POST /api/v1/auth/change-password
exports.changePassword = catchAsync(async (req, res, next) => {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;

  if (newPassword !== confirmNewPassword) {
    return next(new AppError('New passwords do not match', 400));
  }

  const user = await User.findById(req.user.id).select('+password');
  
  if (!await user.comparePassword(currentPassword)) {
    return next(new AppError('Current password is incorrect', 401));
  }

  const isUsedBefore = await user.isPasswordUsedBefore(newPassword);
  if (isUsedBefore) {
    return next(new AppError('Cannot reuse a previous password', 400));
  }

  user.password = newPassword;
  user.activeRefreshTokens = [];
  user.tokenRevokedAt = new Date(); // force logout all devices
  await user.save();

  tokenService.clearRefreshTokenCookie(res);

  res.status(200).json({
    success: true,
    message: 'Password changed successfully. Please login again.'
  });
});

// @desc    Get current user
// @route   GET /api/v1/auth/me
exports.getMe = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  
  res.status(200).json({
    success: true,
    data: { user }
  });
});
