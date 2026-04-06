/**
 * SSEService — Server-Sent Events
 * প্রতিটা logged-in device একটা SSE connection রাখে।
 * যখন কোনো device revoke/logout হয়, এই service সেই device কে
 * real-time এ "force-logout" event পাঠায়।
 */

class SSEService {
  constructor() {
    // Map<userId, Map<deviceId, res>>
    this.connections = new Map();
  }

  // নতুন device connect হলে register করো
  addConnection(userId, deviceId, res) {
    if (!this.connections.has(userId)) {
      this.connections.set(userId, new Map());
    }
    this.connections.get(userId).set(deviceId, res);
  }

  // Device disconnect হলে remove করো
  removeConnection(userId, deviceId) {
    const userConns = this.connections.get(userId);
    if (!userConns) return;
    userConns.delete(deviceId);
    if (userConns.size === 0) this.connections.delete(userId);
  }

  // নির্দিষ্ট একটা device কে event পাঠাও
  sendToDevice(userId, deviceId, event, data) {
    const userConns = this.connections.get(userId);
    if (!userConns) return false;
    const res = userConns.get(deviceId);
    if (!res) return false;
    this._send(res, event, data);
    return true;
  }

  // User এর সব device কে পাঠাও (নিজেকে বাদ দিয়ে)
  sendToAllDevices(userId, event, data, exceptDeviceId = null) {
    const userConns = this.connections.get(userId);
    if (!userConns) return;
    userConns.forEach((res, deviceId) => {
      if (deviceId !== exceptDeviceId) {
        this._send(res, event, data);
      }
    });
  }

  // User এর সব device কে পাঠাও (নিজেকে সহ)
  sendToAllDevicesIncludingSelf(userId, event, data) {
    this.sendToAllDevices(userId, event, data, null);
  }

  // কতটা connection active আছে
  getConnectionCount(userId) {
    return this.connections.get(userId)?.size || 0;
  }

  // SSE format এ data পাঠাও
  _send(res, event, data) {
    try {
      res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    } catch {
      // connection already closed — ignore
    }
  }

  // Heartbeat — connection জীবিত রাখে (30s interval)
  sendHeartbeat(userId, deviceId) {
    const userConns = this.connections.get(userId);
    if (!userConns) return;
    const res = userConns.get(deviceId);
    if (!res) return;
    try {
      res.write(': heartbeat\n\n');
    } catch {
      this.removeConnection(userId, deviceId);
    }
  }
}

module.exports = new SSEService();
