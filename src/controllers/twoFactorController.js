const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto');
const User = require('../models/User');
const { AppError, catchAsync } = require('../utils/errorUtils');

// @desc    Setup 2FA - generate secret and QR code
// @route   POST /api/v1/2fa/setup
exports.setup2FA = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);

  if (user.twoFactorEnabled) {
    return next(new AppError('2FA is already enabled', 400));
  }

  const secret = speakeasy.generateSecret({
    name: `${process.env.TWO_FACTOR_APP_NAME}:${user.email}`,
    issuer: process.env.TWO_FACTOR_APP_NAME || 'AuthSystem',
    length: 20
  });

  // Temporarily store secret (not enabled until verified)
  await User.findByIdAndUpdate(req.user.id, {
    $set: { twoFactorSecret: secret.base32 }
  });

  const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

  res.status(200).json({
    success: true,
    data: {
      secret: secret.base32,
      qrCode: qrCodeDataUrl,
      manualEntryKey: secret.base32.match(/.{1,4}/g).join(' ')
    }
  });
});

// @desc    Enable 2FA - verify code and generate backup codes
// @route   POST /api/v1/2fa/enable
exports.enable2FA = catchAsync(async (req, res, next) => {
  const { totpCode } = req.body;
  
  const user = await User.findById(req.user.id).select('+twoFactorSecret');

  if (!user.twoFactorSecret) {
    return next(new AppError('Please setup 2FA first', 400));
  }

  const isValid = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: totpCode,
    window: 2
  });

  if (!isValid) {
    return next(new AppError('Invalid verification code', 400));
  }

  // Generate backup codes
  const backupCodes = Array.from({ length: 10 }, () => ({
    code: crypto.randomBytes(4).toString('hex').toUpperCase(),
    used: false
  }));

  user.twoFactorEnabled = true;
  user.twoFactorVerifiedAt = new Date();
  user.twoFactorBackupCodes = backupCodes;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    success: true,
    message: '2FA enabled successfully!',
    data: {
      backupCodes: backupCodes.map(bc => bc.code)
    }
  });
});

// @desc    Disable 2FA
// @route   POST /api/v1/2fa/disable
exports.disable2FA = catchAsync(async (req, res, next) => {
  const { totpCode, password } = req.body;
  
  const user = await User.findById(req.user.id).select('+password +twoFactorSecret');

  if (!user.twoFactorEnabled) {
    return next(new AppError('2FA is not enabled', 400));
  }

  // Verify password
  if (!await user.comparePassword(password)) {
    return next(new AppError('Incorrect password', 401));
  }

  // Verify TOTP
  const isValid = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: totpCode,
    window: 2
  });

  if (!isValid) {
    return next(new AppError('Invalid 2FA code', 400));
  }

  user.twoFactorEnabled = false;
  user.twoFactorSecret = undefined;
  user.twoFactorBackupCodes = [];
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    success: true,
    message: '2FA disabled successfully'
  });
});

// @desc    Verify 2FA code (during login)
// @route   POST /api/v1/2fa/verify
exports.verify2FA = catchAsync(async (req, res, next) => {
  const { tempToken, totpCode } = req.body;
  
  const tokenService = require('../services/tokenService');
  
  let decoded;
  try {
    decoded = tokenService.verifyAccessToken(tempToken);
  } catch {
    return next(new AppError('Invalid or expired temporary token', 401));
  }

  if (!decoded.requires2FA) {
    return next(new AppError('Invalid token type', 400));
  }

  const user = await User.findById(decoded.userId).select('+twoFactorSecret +twoFactorBackupCodes');
  
  if (!user) {
    return next(new AppError('User not found', 404));
  }

  // Check TOTP
  const isValidTOTP = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: totpCode,
    window: 2
  });

  if (!isValidTOTP) {
    // Check backup codes
    const backupCode = user.twoFactorBackupCodes.find(bc => !bc.used && bc.code === totpCode);
    if (!backupCode) {
      return next(new AppError('Invalid 2FA code', 401));
    }
    backupCode.used = true;
    backupCode.usedAt = new Date();
    await user.save({ validateBeforeSave: false });
  }

  // Issue real tokens
  const crypto = require('crypto');
  const { accessToken, refreshToken } = tokenService.generateTokenPair({
    userId: user._id.toString(),
    email: user.email,
    role: user.role
  });

  const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
  user.activeRefreshTokens.push({
    token: hashedToken,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
  });
  await user.save({ validateBeforeSave: false });

  tokenService.setRefreshTokenCookie(res, refreshToken);

  res.status(200).json({
    success: true,
    message: '2FA verified successfully',
    data: {
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      }
    }
  });
});

// @desc    Get new backup codes
// @route   POST /api/v1/2fa/backup-codes/regenerate
exports.regenerateBackupCodes = catchAsync(async (req, res, next) => {
  const { totpCode } = req.body;
  const user = await User.findById(req.user.id).select('+twoFactorSecret');

  const isValid = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: totpCode,
    window: 2
  });

  if (!isValid) {
    return next(new AppError('Invalid 2FA code', 401));
  }

  const newBackupCodes = Array.from({ length: 10 }, () => ({
    code: crypto.randomBytes(4).toString('hex').toUpperCase(),
    used: false
  }));

  await User.findByIdAndUpdate(req.user.id, {
    $set: { twoFactorBackupCodes: newBackupCodes }
  });

  res.status(200).json({
    success: true,
    data: {
      backupCodes: newBackupCodes.map(bc => bc.code)
    }
  });
});
