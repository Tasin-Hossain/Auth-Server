const jwt  = require('jsonwebtoken');
const crypto = require('crypto');

class TokenService {

  // Generate Access Token (short-lived — 15 min)
  generateAccessToken(payload) {
    return jwt.sign(
      { ...payload, type: 'access' },
      process.env.JWT_ACCESS_SECRET,
      {
        expiresIn: process.env.JWT_ACCESS_EXPIRE || '15m',
        issuer:    'mern-auth-system',
        audience:  'mern-auth-client',
      }
    );
  }

  // Generate Refresh Token (long-lived — 7 days)
  generateRefreshToken(payload) {
    return jwt.sign(
      { ...payload, type: 'refresh', jti: crypto.randomUUID() },
      process.env.JWT_REFRESH_SECRET,
      {
        expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d',
        issuer:    'mern-auth-system',
      }
    );
  }

  // Verify Access Token
  verifyAccessToken(token) {
    try {
      return jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
        issuer:   'mern-auth-system',
        audience: 'mern-auth-client',
      });
    } catch (err) {
      throw new Error(`Invalid access token: ${err.message}`);
    }
  }

  // Verify Refresh Token
  verifyRefreshToken(token) {
    try {
      return jwt.verify(token, process.env.JWT_REFRESH_SECRET, {
        issuer: 'mern-auth-system',
      });
    } catch (err) {
      throw new Error(`Invalid refresh token: ${err.message}`);
    }
  }

  // ── Cookie helpers 
  _cookieOptions() {
    const isProd = process.env.NODE_ENV === 'production';
    return {
      httpOnly: true,
      secure: false,          // production এ HTTPS (railway uses HTTPS)
      // production এ vercel + railway = cross-site → 'none' লাগবে
      // none হলে secure: true অবশ্যই লাগবে
      sameSite: isProd ? 'none' : 'lax',
      path:     '/',
    };
  }

  setRefreshTokenCookie(res, token) {
    res.cookie('refreshToken', token, {
      ...this._cookieOptions(),
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
  }

  clearRefreshTokenCookie(res) {
    res.cookie('refreshToken', '', {
      ...this._cookieOptions(),
      expires: new Date(0),
    });
  }

  // Generate access + refresh pair
  generateTokenPair(payload) {
    return {
      accessToken:  this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken(payload),
    };
  }

  decode(token) {
    return jwt.decode(token, { complete: true });
  }
}

module.exports = new TokenService();
