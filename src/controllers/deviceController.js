const User       = require('../models/User');
const sseService = require('../services/sseService');
const { AppError, catchAsync } = require('../utils/errorUtils');

// ==================== DEVICE CONTROLLER ====================

// @desc  Get all devices
// @route GET /api/v1/devices
exports.getDevices = catchAsync(async (req, res) => {
  const user = await User.findById(req.user.id).select('devices');
  res.status(200).json({ success: true, data: { devices: user.devices } });
});

// @desc  Trust a device
// @route PATCH /api/v1/devices/:deviceId/trust
exports.trustDevice = catchAsync(async (req, res, next) => {
  const user   = await User.findById(req.user.id);
  const device = user.devices.find(d => d.deviceId === req.params.deviceId);
  if (!device) return next(new AppError('Device not found', 404));

  device.isTrusted = true;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({ success: true, message: 'Device trusted', data: { device } });
});

// @desc  Remove a device → revoke its sessions + SSE force-logout
// @route DELETE /api/v1/devices/:deviceId
exports.removeDevice = catchAsync(async (req, res, next) => {
  const userId   = req.user.id.toString();
  const targetId = req.params.deviceId;

  const user = await User.findById(userId);
  if (!user.devices.some(d => d.deviceId === targetId)) {
    return next(new AppError('Device not found', 404));
  }

  // Remove device + revoke its refresh token
  user.devices             = user.devices.filter(d => d.deviceId !== targetId);
  user.activeRefreshTokens = user.activeRefreshTokens.filter(t => t.deviceId !== targetId);
  await user.save({ validateBeforeSave: false });

  // 🔴 Real-time force-logout — SSE event to that specific device
  sseService.sendToDevice(userId, targetId, 'force-logout', {
    reason: 'device_removed',
    message: 'This device was removed by another session.',
  });

  res.status(200).json({ success: true, message: 'Device removed successfully' });
});

// @desc  Rename a device
// @route PATCH /api/v1/devices/:deviceId/rename
exports.renameDevice = catchAsync(async (req, res, next) => {
  const user   = await User.findById(req.user.id);
  const device = user.devices.find(d => d.deviceId === req.params.deviceId);
  if (!device) return next(new AppError('Device not found', 404));

  device.deviceName = req.body.name;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({ success: true, data: { device } });
});

// ==================== SESSION CONTROLLER ====================

// @desc  Get active sessions
// @route GET /api/v1/sessions
exports.getSessions = catchAsync(async (req, res) => {
  const user     = await User.findById(req.user.id).select('activeRefreshTokens devices');
  const currentDeviceId = req.headers['x-device-id'];

  const sessions = user.activeRefreshTokens.map(token => {
    const device = user.devices.find(d => d.deviceId === token.deviceId);
    return {
      sessionId:  token._id,
      deviceId:   token.deviceId,
      deviceName: device?.deviceName || 'Unknown Device',
      browser:    device?.browser,
      os:         device?.os,
      location:   device?.location,
      isTrusted:  device?.isTrusted || false,
      lastUsed:   device?.lastUsed,
      createdAt:  token.createdAt,
      expiresAt:  token.expiresAt,
      isCurrent:  token.deviceId === currentDeviceId,
    };
  });

  res.status(200).json({ success: true, data: { sessions } });
});

// @desc  Revoke a specific session → SSE force-logout that device
// @route DELETE /api/v1/sessions/:sessionId
exports.revokeSession = catchAsync(async (req, res, next) => {
  const userId = req.user.id.toString();
  const user   = await User.findById(userId);

  const session = user.activeRefreshTokens.find(
    t => t._id.toString() === req.params.sessionId
  );
  if (!session) return next(new AppError('Session not found', 404));

  const revokedDeviceId = session.deviceId;

  // Remove the session
  user.activeRefreshTokens = user.activeRefreshTokens.filter(
    t => t._id.toString() !== req.params.sessionId
  );
  await user.save({ validateBeforeSave: false });

  // 🔴 Real-time force-logout via SSE
  sseService.sendToDevice(userId, revokedDeviceId, 'force-logout', {
    reason:  'session_revoked',
    message: 'Your session was revoked from another device.',
  });

  res.status(200).json({ success: true, message: 'Session revoked successfully' });
});

// @desc  Get login history
// @route GET /api/v1/sessions/history
exports.getLoginHistory = catchAsync(async (req, res) => {
  const user = await User.findById(req.user.id).select('loginHistory');
  res.status(200).json({
    success: true,
    data: { history: user.loginHistory, total: user.loginHistory.length },
  });
});
