const speakeasy = require('speakeasy');
const QRCode    = require('qrcode');
const crypto    = require('crypto');
const User      = require('../models/User');
const { AppError, catchAsync } = require('../utils/errorUtils');
const tokenService = require('../services/tokenService');

// @desc  Setup 2FA — generate secret + QR
exports.setup2FA = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (user.twoFactorEnabled) return next(new AppError('2FA is already enabled', 400));

  const secret = speakeasy.generateSecret({
    name: `${process.env.TWO_FACTOR_APP_NAME || 'AuthSystem'}:${user.email}`,
    issuer: process.env.TWO_FACTOR_APP_NAME || 'AuthSystem',
    length: 20,
  });

  await User.findByIdAndUpdate(req.user.id, { twoFactorSecret: secret.base32 });

  const qrCode = await QRCode.toDataURL(secret.otpauth_url);

  res.status(200).json({
    success: true,
    data: {
      secret: secret.base32,
      qrCode,
      manualEntryKey: secret.base32.match(/.{1,4}/g).join(' '),
    },
  });
});

// @desc  Enable 2FA — verify code, generate backup codes
exports.enable2FA = catchAsync(async (req, res, next) => {
  const { totpCode } = req.body;
  const user = await User.findById(req.user.id).select('+twoFactorSecret');

  if (!user.twoFactorSecret) return next(new AppError('Please setup 2FA first', 400));

  const isValid = speakeasy.totp.verify({
    secret: user.twoFactorSecret, encoding: 'base32', token: totpCode, window: 2,
  });
  if (!isValid) return next(new AppError('Invalid verification code', 400));

  const backupCodes = Array.from({ length: 10 }, () => ({
    code: crypto.randomBytes(4).toString('hex').toUpperCase(),
    used: false,
  }));

  user.twoFactorEnabled    = true;
  user.twoFactorVerifiedAt = new Date();
  user.twoFactorBackupCodes = backupCodes;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    success: true,
    message: '2FA enabled!',
    data: { backupCodes: backupCodes.map(bc => bc.code) },
  });
});

// @desc  Disable 2FA
exports.disable2FA = catchAsync(async (req, res, next) => {
  const { totpCode, password } = req.body;
  const user = await User.findById(req.user.id).select('+password +twoFactorSecret');

  if (!user.twoFactorEnabled) return next(new AppError('2FA is not enabled', 400));
  if (!await user.comparePassword(password)) return next(new AppError('Incorrect password', 401));

  const isValid = speakeasy.totp.verify({
    secret: user.twoFactorSecret, encoding: 'base32', token: totpCode, window: 2,
  });
  if (!isValid) return next(new AppError('Invalid 2FA code', 400));

  user.twoFactorEnabled     = false;
  user.twoFactorSecret      = undefined;
  user.twoFactorBackupCodes = [];
  await user.save({ validateBeforeSave: false });

  res.status(200).json({ success: true, message: '2FA disabled' });
});

// @desc  Verify 2FA during login (tempToken → real tokens)
exports.verify2FA = catchAsync(async (req, res, next) => {
  const { tempToken, totpCode } = req.body;

  // 1. Verify temp token
  let decoded;
  try {
    decoded = tokenService.verifyAccessToken(tempToken);
  } catch {
    return next(new AppError('Invalid or expired temporary token', 401));
  }
  if (!decoded.requires2FA) return next(new AppError('Invalid token type', 400));

  // 2. Restore deviceInfo from tempToken (was stored during login step 1)
  const deviceInfo = {
    deviceId:  decoded.deviceId  || require('crypto').randomUUID(),
    ip:        decoded.ip        || '0.0.0.0',
    location:  decoded.location  || 'Unknown',
    browser:   decoded.browser   || 'Unknown',
    os:        decoded.os        || 'Unknown',
    userAgent: decoded.userAgent || '',
  };
  const riskScore      = decoded.riskScore    || 0;
  const riskLevel      = decoded.riskLevel    || 'low';
  const riskFlags      = decoded.riskFlags    || [];
  const isKnownDevice  = decoded.isKnownDevice || false;
  const trustDevice    = decoded.trustDevice   || false;

  // 3. Load user
  const user = await User.findById(decoded.userId)
    .select('+twoFactorSecret +twoFactorBackupCodes');
  if (!user) return next(new AppError('User not found', 404));

  // 4. Verify TOTP or backup code
  const isValidTOTP = speakeasy.totp.verify({
    secret: user.twoFactorSecret, encoding: 'base32', token: totpCode, window: 2,
  });

  if (!isValidTOTP) {
    const backup = user.twoFactorBackupCodes?.find(bc => !bc.used && bc.code === totpCode);
    if (!backup) {
      // Log failed 2FA attempt
      await user.addLoginHistory({
        ...deviceInfo,
        success: false,
        failReason: 'wrong_2fa_code',
        riskScore,
      });
      return next(new AppError('Invalid 2FA code', 401));
    }
    backup.used   = true;
    backup.usedAt = new Date();
  }

  // 5. Update device list (same logic as normal login)
  user.devices = user.devices || [];
  const existingDevice = user.devices.find(d => d.deviceId === deviceInfo.deviceId);
  const isNewDevice    = !existingDevice;

  if (existingDevice) {
    existingDevice.lastUsed  = new Date();
    existingDevice.ip        = deviceInfo.ip;
    existingDevice.location  = deviceInfo.location;
  } else {
    user.devices.push({
      deviceId:   deviceInfo.deviceId,
      deviceName: `${deviceInfo.browser} on ${deviceInfo.os}`,
      browser:    deviceInfo.browser,
      os:         deviceInfo.os,
      ip:         deviceInfo.ip,
      location:   deviceInfo.location,
      userAgent:  deviceInfo.userAgent,
      isTrusted:  trustDevice,
    });
    if (user.devices.length > 10) user.devices = user.devices.slice(-10);
  }

  // 6. Update user security fields
  user.lastLogin  = new Date();
  user.lastIp     = deviceInfo.ip;
  user.riskScore  = riskScore;
  if (riskScore >= 50) {
    user.isSuspicious   = true;
    user.suspiciousFlags = [...new Set([...(user.suspiciousFlags || []), ...riskFlags])];
  }

  // 7. Add login history ★ THIS WAS MISSING
  await user.addLoginHistory({
    ...deviceInfo,
    success:   true,
    riskScore,
  });

  // 8. Generate real token pair
  const { accessToken, refreshToken } = tokenService.generateTokenPair({
    userId:   user._id.toString(),
    email:    user.email,
    role:     user.role,
    deviceId: deviceInfo.deviceId,
  });

  // 9. Store refresh token
  user.activeRefreshTokens = (user.activeRefreshTokens || []).filter(t => t.expiresAt > new Date());
  user.activeRefreshTokens.push({
    token:     crypto.createHash('sha256').update(refreshToken).digest('hex'),
    deviceId:  deviceInfo.deviceId,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
  if (user.activeRefreshTokens.length > 5) user.activeRefreshTokens = user.activeRefreshTokens.slice(-5);

  await user.save({ validateBeforeSave: false });

  tokenService.setRefreshTokenCookie(res, refreshToken);

  // 10. Return full user — same shape as normal login
  res.status(200).json({
    success: true,
    message: '2FA verified',
    data: {
      accessToken,
      user: {
        id:               user._id,
        firstName:        user.firstName,
        lastName:         user.lastName,
        email:            user.email,
        role:             user.role,
        avatar:           user.avatar,
        isEmailVerified:  user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
        lastLogin:        user.lastLogin,
      },
      security: {
        riskScore,
        riskLevel,
        isNewDevice,
      },
    },
  });
});

// @desc  Regenerate backup codes
exports.regenerateBackupCodes = catchAsync(async (req, res, next) => {
  const { totpCode } = req.body;
  const user = await User.findById(req.user.id).select('+twoFactorSecret');

  const isValid = speakeasy.totp.verify({
    secret: user.twoFactorSecret, encoding: 'base32', token: totpCode, window: 2,
  });
  if (!isValid) return next(new AppError('Invalid 2FA code', 401));

  const newCodes = Array.from({ length: 10 }, () => ({
    code: crypto.randomBytes(4).toString('hex').toUpperCase(),
    used: false,
  }));

  await User.findByIdAndUpdate(req.user.id, { twoFactorBackupCodes: newCodes });

  res.status(200).json({
    success: true,
    data: { backupCodes: newCodes.map(bc => bc.code) },
  });
});
