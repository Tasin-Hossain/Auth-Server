const logger   = require('../config/logger');
const RiskLog  = require('../models/RiskLog');

class FraudDetectionService {

  async analyzeLoginRisk(user, loginData) {
      console.log("🔥 analyzeLoginRisk CALLED");
      console.log("User:", user.email);

    const { ip, location, deviceId, isKnownDevice } = loginData;
    let heuristicScore = 0;
    const flags = [];

    // ── Heuristic checks ─────────────────────────────────────────────────────
    if ((user.failedLoginAttempts || 0) >= 3) {
      heuristicScore += 20; flags.push('multiple_failed_attempts');
    }
    if (!isKnownDevice && (user.devices?.length || 0) > 0) {
      heuristicScore += 15; flags.push('new_device');
    }
    const lastLocation = user.loginHistory?.[0]?.location;
    if (lastLocation && location && lastLocation !== location && location !== 'Unknown') {
      heuristicScore += 20; flags.push('location_change');
    }
    const hour = new Date().getUTCHours();
    if (hour >= 2 && hour <= 5) {
      heuristicScore += 10; flags.push('unusual_hour');
    }
    const recentIPs = new Set((user.loginHistory || []).slice(0, 5).map(l => l.ip)).size;
    if (recentIPs > 3) {
      heuristicScore += 25; flags.push('multiple_ips');
    }
    const ageHours = (Date.now() - new Date(user.createdAt)) / 3_600_000;
    if (ageHours < 1) {
      heuristicScore += 10; flags.push('new_account');
    }
    if (user.isSuspicious) {
      heuristicScore += 30; flags.push('previously_flagged');
    }

    heuristicScore = Math.min(100, heuristicScore);

    // ── AI check (Gemini) ─────────────────────────────────────────────────────
    let aiScore  = 0;
    let aiUsed   = false;
    let aiModel  = '';
    let finalScore = heuristicScore;

    if (process.env.GEMINI_API_KEY && heuristicScore > 30) {
      try {
        aiScore = await this.getGeminiRiskScore(user, loginData, flags);
        aiUsed  = true;
        aiModel = 'gemini-2.0-flash';
        finalScore = Math.min(100, Math.round((heuristicScore + aiScore) / 2));
        if (aiScore > 50) flags.push('ai_flagged');
        logger.info(`[AI Fraud] user=${user.email} heuristic=${heuristicScore} ai=${aiScore} final=${finalScore}`);
      } catch (aiErr) {
        if (aiErr.message.includes('429')) {
          logger.warn("🚫 Rate limit hit (429), skipping AI...");
        } else {
          logger.warn(`[AI Fraud] Gemini error: ${aiErr.message}`);
        }
      }
    } else if (!process.env.GEMINI_API_KEY) {
      logger.debug(`[Fraud] GEMINI_API_KEY not set — heuristic only. Score=${heuristicScore}`);
    }

    finalScore = Math.min(100, finalScore);
    const riskLevel = finalScore < 25 ? 'low' : finalScore < 50 ? 'medium' : finalScore < 75 ? 'high' : 'critical';

    const action = finalScore >= 80 ? 'blocked'
      : finalScore >= 50 ? 'alerted'
      : finalScore >= 40 ? '2fa_required'
      : 'allowed';

    // ── Save to RiskLog ───────────────────────────────────────────────────────
    this._saveLog({
      userId:         user._id,
      email:          user.email,
      ip:             loginData.ip,
      location:       loginData.location,
      browser:        loginData.browser,
      os:             loginData.os,
      deviceId:       loginData.deviceId,
      heuristicScore,
      heuristicFlags: flags,
      aiUsed,
      aiScore,
      aiModel,
      finalScore,
      riskLevel,
      action,
      loginSuccess:   null, // authController এ update করবে
    });

    logger.info(
      `[Fraud] user=${user.email} ip=${loginData.ip} ` +
      `heuristic=${heuristicScore} ai=${aiUsed ? aiScore : 'N/A'} ` +
      `final=${finalScore} level=${riskLevel} action=${action} ` +
      `flags=[${flags.join(', ')}]`
    );

    return {
      riskScore:    finalScore,
      riskLevel,
      flags,
      shouldBlock:  finalScore >= 80,
      shouldAlert:  finalScore >= 50,
      require2FA:   finalScore >= 40,
    };
  }

  // Gemini Free API
  async getGeminiRiskScore(user, loginData, existingFlags) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${process.env.GEMINI_API_KEY}`;

    const prompt = `You are a login fraud detection system. Analyze and return ONLY JSON.

Data:
- Failed attempts: ${user.failedLoginAttempts || 0}
- Account age days: ${Math.floor((Date.now() - new Date(user.createdAt)) / 86_400_000)}
- Known device: ${loginData.isKnownDevice ? 'yes' : 'no'}
- Location change: ${existingFlags.includes('location_change') ? 'yes' : 'no'}
- Multiple IPs: ${existingFlags.includes('multiple_ips') ? 'yes' : 'no'}
- Unusual hour: ${existingFlags.includes('unusual_hour') ? 'yes' : 'no'}
- Flags: ${existingFlags.join(', ') || 'none'}

Respond ONLY: {"riskScore": NUMBER_0_TO_100}`;

    const res = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens: 30, temperature: 0.1 },
      }),
      signal: AbortSignal.timeout(5000), // 5s timeout
    });

    if (!res.ok) throw new Error(`Gemini API ${res.status}`);

    const data  = await res.json();
    const text  = data?.candidates?.[0]?.content?.parts?.[0]?.text || '{"riskScore":0}';
    const clean = text.replace(/```json|```/g, '').trim();
    const score = JSON.parse(clean).riskScore || 0;
    return Math.min(100, Math.max(0, score));
  }

  async analyzeRegistrationRisk({ email }) {
    const disposable = ['tempmail.com','throwaway.email','guerrillamail.com','mailnator.com','10minutemail.com','yopmail.com'];
    const domain = email.split('@')[1]?.toLowerCase() || '';
    if (disposable.includes(domain)) return { riskScore: 80, flags: ['disposable_email'], shouldBlock: true };
    return { riskScore: 0, flags: [], shouldBlock: false };
  }

  // Fire-and-forget log save
  _saveLog(data) {
    RiskLog.create(data).catch(e => logger.error('[Fraud] RiskLog save failed:', e));
  }
}

module.exports = new FraudDetectionService();
