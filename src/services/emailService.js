const nodemailer = require("nodemailer");
const logger = require("../config/logger");

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
  }

  async sendEmail({ to, subject, html, text }) {
    try {
      const mailOptions = {
        from: process.env.EMAIL_FROM,
        to,
        subject,
        html,
        text: text || html.replace(/<[^>]*>/g, ""),
      };

      const info = await this.transporter.sendMail(mailOptions);
      logger.info(`Email sent to ${to}: ${info.messageId}`);
      return info;
    } catch (error) {
      logger.error("Email send error:", error);
      throw new Error("Email could not be sent");
    }
  }

  // Email Verification
  async sendVerificationEmail(user, token) {
    const verifyUrl = `${process.env.CLIENT_URL}/verify-email/${token}`;

    await this.sendEmail({
      to: user.email,
      subject: "✅ Verify Your Email Address",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0f0f0f; color: #fff; padding: 40px; border-radius: 12px;">
          <div style="text-align: center; margin-bottom: 32px;">
            <h1 style="color: #6366f1; font-size: 28px; margin: 0;">🔐 AuthSystem</h1>
          </div>
          <h2 style="color: #fff; font-size: 22px;">Verify your email</h2>
          <p style="color: #a1a1aa; line-height: 1.6;">Hi ${user.firstName}, please click the button below to verify your email address. This link expires in 24 hours.</p>
          <div style="text-align: center; margin: 32px 0;">
            <a href="${verifyUrl}" style="background: #6366f1; color: #fff; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 16px; display: inline-block;">Verify Email</a>
          </div>
          <p style="color: #52525b; font-size: 12px;">If you didn't create an account, please ignore this email.</p>
          <p style="color: #52525b; font-size: 12px; word-break: break-all;">Or copy this link: ${verifyUrl}</p>
        </div>
      `,
    });
  }

  // Password Reset
  async sendPasswordResetEmail(user, token) {
    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${token}`;

    await this.sendEmail({
      to: user.email,
      subject: "🔑 Password Reset Request",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0f0f0f; color: #fff; padding: 40px; border-radius: 12px;">
          <div style="text-align: center; margin-bottom: 32px;">
            <h1 style="color: #6366f1; font-size: 28px; margin: 0;">🔐 AuthSystem</h1>
          </div>
          <h2 style="color: #fff;">Reset your password</h2>
          <p style="color: #a1a1aa; line-height: 1.6;">Hi ${user.firstName}, you requested a password reset. This link expires in 10 minutes.</p>
          <div style="text-align: center; margin: 32px 0;">
            <a href="${resetUrl}" style="background: #ef4444; color: #fff; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 16px; display: inline-block;">Reset Password</a>
          </div>
          <p style="color: #52525b; font-size: 12px;">If you didn't request this, please ignore this email and your password will remain unchanged.</p>
          <p style="color: #52525b; font-size: 12px; word-break: break-all;">Or copy: ${resetUrl}</p>
        </div>
      `,
    });
  }

  // 2FA OTP
  async send2FACode(user, otp) {
    await this.sendEmail({
      to: user.email,
      subject: "🔒 Your 2FA Verification Code",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0f0f0f; color: #fff; padding: 40px; border-radius: 12px;">
          <h1 style="color: #6366f1;">🔐 AuthSystem</h1>
          <h2 style="color: #fff;">Your verification code</h2>
          <p style="color: #a1a1aa;">Hi ${user.firstName}, use this code to complete your sign-in:</p>
          <div style="background: #18181b; border: 2px solid #6366f1; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0;">
            <span style="font-size: 48px; font-weight: bold; letter-spacing: 16px; color: #6366f1; font-family: monospace;">${otp}</span>
          </div>
          <p style="color: #a1a1aa;">This code expires in <strong style="color: #fff;">5 minutes</strong>.</p>
          <p style="color: #ef4444; font-size: 12px;">⚠️ Never share this code with anyone.</p>
        </div>
      `,
    });
  }

  // Suspicious activity alert
  async sendSuspiciousActivityAlert(user, activity) {
    await this.sendEmail({
      to: user.email,
      subject: "⚠️ Suspicious Activity Detected",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0f0f0f; color: #fff; padding: 40px; border-radius: 12px;">
          <h1 style="color: #ef4444;">⚠️ Security Alert</h1>
          <h2 style="color: #fff;">Suspicious activity on your account</h2>
          <p style="color: #a1a1aa;">Hi ${user.firstName}, we detected unusual activity on your account:</p>
          <div style="background: #18181b; border-left: 4px solid #ef4444; padding: 16px; margin: 16px 0;">
            <p style="color: #fca5a5; margin: 0;"><strong>Activity:</strong> ${activity.type}</p>
            <p style="color: #a1a1aa; margin: 4px 0;"><strong>IP Address:</strong> ${activity.ip}</p>
            <p style="color: #a1a1aa; margin: 4px 0;"><strong>Location:</strong> ${activity.location || "Unknown"}</p>
            <p style="color: #a1a1aa; margin: 4px 0;"><strong>Time:</strong> ${new Date().toLocaleString()}</p>
          </div>
          <p style="color: #a1a1aa;">If this was you, you can ignore this email. If not, please secure your account immediately.</p>
          <div style="text-align: center; margin: 24px 0;">
            <a href="${process.env.CLIENT_URL}/dashboard/security" style="background: #ef4444; color: #fff; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold;">Secure My Account</a>
          </div>
        </div>
      `,
    });
  }

  // New device login
  async sendNewDeviceAlert(user, device) {
    await this.sendEmail({
      to: user.email,
      subject: "🔔 New Device Login",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0f0f0f; color: #fff; padding: 40px; border-radius: 12px;">
          <h1 style="color: #6366f1;">🔐 AuthSystem</h1>
          <h2 style="color: #fff;">New device login detected</h2>
          <p style="color: #a1a1aa;">Hi ${user.firstName}, a new device just signed in to your account:</p>
          <div style="background: #18181b; border-radius: 8px; padding: 16px; margin: 16px 0;">
            <p style="color: #d4d4d8; margin: 4px 0;">📱 <strong>Device:</strong> ${device.browser} on ${device.os}</p>
            <p style="color: #d4d4d8; margin: 4px 0;">🌍 <strong>Location:</strong> ${device.location || "Unknown"}</p>
            <p style="color: #d4d4d8; margin: 4px 0;">🕐 <strong>Time:</strong> ${new Date().toLocaleString()}</p>
          </div>
          <p style="color: #a1a1aa;">Not you? <a href="${process.env.CLIENT_URL}/dashboard/security" style="color: #6366f1;">Secure your account</a> immediately.</p>
        </div>
      `,
    });
  }
}

module.exports = new EmailService();
