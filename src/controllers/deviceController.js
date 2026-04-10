const User = require('../models/User');
const { AppError, catchAsync } = require('../utils/errorUtils');

// @desc  Get all devices
exports.getDevices = catchAsync(async (req, res) => {
  const user = await User.findById(req.user.id).select('devices');
  res.status(200).json({ success: true, data: { devices: user.devices || [] } });
});

// @desc  Trust a device
exports.trustDevice = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  const device = user.devices?.find(d => d.deviceId === req.params.deviceId);
  if (!device) return next(new AppError('Device not found', 404));
  device.isTrusted = true;
  device.trustedAt = new Date();
  await user.save({ validateBeforeSave: false });
  res.status(200).json({ success: true, message: 'Device trusted ✅', data: { device } });
});

// @desc  Untrust a device
exports.untrustDevice = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  const device = user.devices?.find(d => d.deviceId === req.params.deviceId);
  if (!device) return next(new AppError('Device not found', 404));
  device.isTrusted = false;
  device.trustedAt = undefined;
  await user.save({ validateBeforeSave: false });
  res.status(200).json({ success: true, message: 'Device untrusted', data: { device } });
});

// @desc  Rename a device
exports.renameDevice = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  const device = user.devices?.find(d => d.deviceId === req.params.deviceId);
  if (!device) return next(new AppError('Device not found', 404));
  device.deviceName = req.body.name?.trim() || device.deviceName;
  await user.save({ validateBeforeSave: false });
  res.status(200).json({ success: true, data: { device } });
});

// @desc  Remove a device (force logout that device)
exports.removeDevice = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  const exists = user.devices?.some(d => d.deviceId === req.params.deviceId);
  if (!exists) return next(new AppError('Device not found', 404));

  user.devices = user.devices.filter(d => d.deviceId !== req.params.deviceId);
  user.activeRefreshTokens = (user.activeRefreshTokens || []).filter(t => t.deviceId !== req.params.deviceId);
  // Force logout the removed device immediately
  user.tokenRevokedAt = new Date();
  await user.save({ validateBeforeSave: false });

  res.status(200).json({ success: true, message: 'Device removed and session revoked' });
});

// @desc  Get sessions
exports.getSessions = catchAsync(async (req, res) => {
  const user = await User.findById(req.user.id).select('activeRefreshTokens devices');
  const currentDeviceId = req.headers['x-device-id'];

  const sessions = (user.activeRefreshTokens || []).map(token => {
    const device = user.devices?.find(d => d.deviceId === token.deviceId);
    return {
      sessionId: token._id,
      deviceId: token.deviceId,
      deviceName: device?.deviceName || 'Unknown Device',
      browser: device?.browser || 'Unknown',
      os: device?.os || 'Unknown',
      location: device?.location || 'Unknown',
      ip: device?.ip,
      isTrusted: device?.isTrusted || false,
      lastUsed: device?.lastUsed,
      createdAt: token.createdAt,
      expiresAt: token.expiresAt,
      isCurrent: token.deviceId === currentDeviceId,
    };
  });

  res.status(200).json({ success: true, data: { sessions } });
});

// @desc  Revoke a session
exports.revokeSession = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  const session = user.activeRefreshTokens?.find(t => t._id.toString() === req.params.sessionId);
  if (!session) return next(new AppError('Session not found', 404));

  user.activeRefreshTokens = user.activeRefreshTokens.filter(t => t._id.toString() !== req.params.sessionId);
  user.tokenRevokedAt = new Date(); // force logout that device
  await user.save({ validateBeforeSave: false });

  res.status(200).json({ success: true, message: 'Session revoked' });
});

// @desc  Login history
exports.getLoginHistory = catchAsync(async (req, res) => {
  const user = await User.findById(req.user.id).select('loginHistory');
  res.status(200).json({ success: true, data: { history: user.loginHistory || [], total: user.loginHistory?.length || 0 } });
});
