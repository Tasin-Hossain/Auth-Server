const logger = require("../config/logger");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

class FraudDetectionService {
  // Analyze login attempt risk using heuristics + optional AI
  async analyzeLoginRisk(user, loginData) {
    const { ip, userAgent, location, deviceId } = loginData;
    let riskScore = 0;
    const flags = [];

    try {
      // 1. Multiple failed attempts
      if (user.failedLoginAttempts >= 3) {
        riskScore += 20;
        flags.push("multiple_failed_attempts");
      }

      // 2. New device
      const isKnownDevice = user.devices.some((d) => d.deviceId === deviceId);
      if (!isKnownDevice && user.devices.length > 0) {
        riskScore += 15;
        flags.push("new_device");
      }

      // 3. Unusual location
      const lastLocation = user.loginHistory[0]?.location;
      if (lastLocation && location && lastLocation !== location) {
        riskScore += 20;
        flags.push("location_change");
      }

      // 4. Login at unusual hours (2 AM - 5 AM local time estimation)
      const hour = new Date().getUTCHours();
      if (hour >= 2 && hour <= 5) {
        riskScore += 10;
        flags.push("unusual_hour");
      }

      // 5. Rapid login from different IPs
      const recentLogins = user.loginHistory.slice(0, 5);
      const uniqueIPs = new Set(recentLogins.map((l) => l.ip)).size;
      if (uniqueIPs > 3) {
        riskScore += 25;
        flags.push("multiple_ips");
      }

      // 6. Account very recently created
      const accountAge = Date.now() - new Date(user.createdAt).getTime();
      const ageInHours = accountAge / (1000 * 60 * 60);
      if (ageInHours < 1) {
        riskScore += 10;
        flags.push("new_account");
      }

      // 7. Previously flagged as suspicious
      if (user.isSuspicious) {
        riskScore += 30;
        flags.push("previously_flagged");
      }

      // 8. Try AI Analysis if API key available
      if (process.env.GEMINI_API_KEY && riskScore > 20) {
        const aiScore = await this.getAIRiskScore(user, loginData, flags);
        riskScore = Math.min(100, Math.round((riskScore + aiScore) / 2));
        if (aiScore > 50) flags.push("ai_flagged");
      }

      const riskLevel = this.getRiskLevel(riskScore);

      return {
        riskScore: Math.min(100, riskScore),
        riskLevel,
        flags,
        shouldBlock: riskScore >= 80,
        shouldAlert: riskScore >= 50,
        require2FA: riskScore >= 40,
      };
    } catch (error) {
      logger.error("Fraud detection error:", error);
      return {
        riskScore: 0,
        riskLevel: "low",
        flags: [],
        shouldBlock: false,
        shouldAlert: false,
      };
    }
  }

  // ✅ Gemini AI version (FIXED)
  async getAIRiskScore(user, loginData, existingFlags) {
    try {
      const model = genAI.getGenerativeModel({
        model: "gemini-1.5-flash",
      });

      const prompt = `
You are a fraud detection system.

Return ONLY JSON:
{"riskScore": number (0-100)}

Login data:
- Failed attempts: ${user.failedLoginAttempts}
- Account age days: ${Math.floor((Date.now() - new Date(user.createdAt)) / 86400000)}
- Known device: ${user.devices.some((d) => d.deviceId === loginData.deviceId) ? "yes" : "no"}
- Location change: ${existingFlags.includes("location_change") ? "yes" : "no"}
- Multiple IPs recently: ${existingFlags.includes("multiple_ips") ? "yes" : "no"}
- Unusual hour: ${existingFlags.includes("unusual_hour") ? "yes" : "no"}
- Existing flags: ${existingFlags.join(", ")}

Respond ONLY with: {"riskScore": NUMBER}
`;

      const result = await model.generateContent(prompt);
      const text = result.response.text();

      const parsed = JSON.parse(text.replace(/```json|```/g, "").trim());

      return parsed.riskScore || 0;
    } catch (error) {
      logger.error("AI fraud detection error:", error);
      return 0;
    }
  }

  getRiskLevel(score) {
    if (score >= 75) return "critical";
    if (score >= 50) return "high";
    if (score >= 25) return "medium";
    return "low";
  }

  // Detect suspicious patterns in registration
  async analyzeRegistrationRisk(registrationData) {
    const { email, ip } = registrationData;
    let riskScore = 0;
    const flags = [];

    // Disposable email domains
    const disposableDomains = [
      "tempmail.com",
      "throwaway.email",
      "guerrillamail.com",
      "mailnator.com",
      "10minutemail.com",
    ];
    const emailDomain = email.split("@")[1]?.toLowerCase();
    if (disposableDomains.includes(emailDomain)) {
      riskScore += 50;
      flags.push("disposable_email");
    }

    return { riskScore, flags, shouldBlock: riskScore >= 70 };
  }
}

module.exports = new FraudDetectionService();
