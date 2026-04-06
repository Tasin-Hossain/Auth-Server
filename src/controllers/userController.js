const User = require('../models/User');
const { AppError, catchAsync } = require('../utils/errorUtils');

// @desc    Update profile
// @route   PATCH /api/v1/users/profile
exports.updateProfile = catchAsync(async (req, res, next) => {
  const allowedFields = ['firstName', 'lastName', 'phone', 'timezone', 'language', 'avatar'];
  const updates = {};
  
  allowedFields.forEach(field => {
    if (req.body[field] !== undefined) updates[field] = req.body[field];
  });

  const user = await User.findByIdAndUpdate(
    req.user.id,
    { $set: updates },
    { new: true, runValidators: true }
  );

  res.status(200).json({
    success: true,
    message: 'Profile updated successfully',
    data: { user }
  });
});

// @desc    Get security overview
// @route   GET /api/v1/users/security
exports.getSecurityOverview = catchAsync(async (req, res) => {
  const user = await User.findById(req.user.id)
    .select('twoFactorEnabled devices activeRefreshTokens loginHistory riskScore isSuspicious suspiciousFlags fraudAlerts lastLogin lastIp isEmailVerified');
  
  const recentFailedLogins = user.loginHistory.filter(h => !h.success).slice(0, 5);
  const activeSessions = user.activeRefreshTokens.length;
  const trustedDevices = user.devices.filter(d => d.isTrusted).length;

  res.status(200).json({
    success: true,
    data: {
      twoFactorEnabled: user.twoFactorEnabled,
      isEmailVerified: user.isEmailVerified,
      activeSessions,
      trustedDevices,
      totalDevices: user.devices.length,
      riskScore: user.riskScore,
      isSuspicious: user.isSuspicious,
      suspiciousFlags: user.suspiciousFlags,
      recentFailedLogins,
      unresolveFraudAlerts: user.fraudAlerts.filter(a => !a.resolved).length,
      lastLogin: user.lastLogin,
      lastIp: user.lastIp
    }
  });
});

// @desc    Admin: get all users
// @route   GET /api/v1/users (admin only)
exports.getAllUsers = catchAsync(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const skip = (page - 1) * limit;

  const users = await User.find()
    .select('-password -twoFactorSecret -twoFactorBackupCodes')
    .sort('-createdAt')
    .skip(skip)
    .limit(limit);

  const total = await User.countDocuments();

  res.status(200).json({
    success: true,
    data: {
      users,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    }
  });
});

// @desc    Delete account
// @route   DELETE /api/v1/users/me
exports.deleteAccount = catchAsync(async (req, res, next) => {
  const { password } = req.body;
  const user = await User.findById(req.user.id).select('+password');
  
  if (!await user.comparePassword(password)) {
    return next(new AppError('Incorrect password', 401));
  }

  await User.findByIdAndDelete(req.user.id);

  res.status(200).json({
    success: true,
    message: 'Account deleted successfully'
  });
});
