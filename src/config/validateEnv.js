const validateEnv = () => {
  const required = [
    "NODE_ENV",
    "PORT",
    "MONGODB_URI",
    "JWT_ACCESS_SECRET",
    "JWT_REFRESH_SECRET",
    "JWT_ACCESS_EXPIRE",
    "JWT_REFRESH_EXPIRE",
    "CLIENT_URL",
    "ENCRYPTION_KEY",
  ];

  // Warn for optional but recommended vars
  const recommended = [
    "EMAIL_HOST",
    "EMAIL_PORT",
    "EMAIL_USER",
    "EMAIL_PASS",
    "EMAIL_FROM",
    "TWO_FACTOR_APP_NAME",
  ];

  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    console.error("\n❌  Missing required environment variables:");
    missing.forEach((key) => console.error(`    → ${key}`));
    console.error(
      "\n   Please set these in your .env file or Railway/Render Variables tab.\n",
    );
    process.exit(1);
  }

  const missingRec = recommended.filter((key) => !process.env[key]);
  if (missingRec.length > 0) {
    console.warn(
      "⚠️  Missing recommended variables (some features may not work):",
    );
    missingRec.forEach((key) => console.warn(`    → ${key}`));
  }
};

module.exports = validateEnv;
