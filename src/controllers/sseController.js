const sseService = require('../services/sseService');
const { catchAsync } = require('../utils/errorUtils');

/**
 * GET /api/v1/events
 * Protected route — প্রতিটা logged-in device এখানে connect করে।
 * Connection জীবিত থাকে যতক্ষণ browser open আছে।
 */
exports.subscribe = catchAsync(async (req, res) => {
  const userId   = req.user._id.toString();
  const deviceId = req.headers['x-device-id'] || 'unknown';

  // SSE headers
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // nginx buffering off
  res.flushHeaders();

  // Register this connection
  sseService.addConnection(userId, deviceId, res);

  // Initial "connected" event
  res.write(`event: connected\n`);
  res.write(`data: ${JSON.stringify({ deviceId, timestamp: Date.now() })}\n\n`);

  // Heartbeat every 25 seconds (keeps connection alive through proxies)
  const heartbeatInterval = setInterval(() => {
    sseService.sendHeartbeat(userId, deviceId);
  }, 25000);

  // Cleanup when client disconnects
  req.on('close', () => {
    clearInterval(heartbeatInterval);
    sseService.removeConnection(userId, deviceId);
  });

  req.on('error', () => {
    clearInterval(heartbeatInterval);
    sseService.removeConnection(userId, deviceId);
  });
});
