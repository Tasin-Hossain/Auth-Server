const crypto = require('crypto');
const RevokedToken = require('../models/RevokedToken');
const logger = require('../config/logger');

class TokenBlacklistService {

  // একটা specific access token revoke করো
  async revokeAccessToken(token, userId, reason = 'logout') {
    try {
      const jwt = require('jsonwebtoken');
      const decoded = jwt.decode(token);
      if (!decoded) return;

      const jti = decoded.jti || this._hashToken(token); // jti না থাকলে hash use করো
      const expiresAt = decoded.exp
        ? new Date(decoded.exp * 1000)
        : new Date(Date.now() + 15 * 60 * 1000); // default 15 min

      await RevokedToken.findOneAndUpdate(
        { jti },
        { jti, userId, reason, expiresAt },
        { upsert: true, new: true }
      );
    } catch (err) {
      logger.error('Token blacklist error:', err);
    }
  }

  // একজন user এর সব active access token revoke করো
  // User model এ tokenRevokedAt timestamp store করাই best approach
  async revokeAllForUser(userId, reason = 'logout_all') {
    try {
      // User এর tokenRevokedAt update করো
      // protect middleware এ এই timestamp check করবে
      const User = require('../models/User');
      await User.findByIdAndUpdate(userId, {
        tokenRevokedAt: new Date()
      });
      logger.info(`All tokens revoked for user ${userId} — reason: ${reason}`);
    } catch (err) {
      logger.error('Revoke all tokens error:', err);
    }
  }

  // Check করো token blacklist এ আছে কিনা
  async isRevoked(token) {
    try {
      const jwt = require('jsonwebtoken');
      const decoded = jwt.decode(token);
      if (!decoded) return true;

      const jti = decoded.jti || this._hashToken(token);
      const found = await RevokedToken.findOne({ jti }).lean();
      return !!found;
    } catch (err) {
      logger.error('Blacklist check error:', err);
      return false; // error হলে block করবো না — availability > security
    }
  }

  // Token এর hash বানাও (jti না থাকলে)
  _hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex').slice(0, 32);
  }
}

module.exports = new TokenBlacklistService();
