require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const connectDB = require('./src/config/database');
const logger = require('./src/config/logger');
const { globalErrorHandler, notFound } = require('./src/middleware/errorMiddleware');

// Routes
const authRoutes = require('./src/routes/authRoutes');
const userRoutes = require('./src/routes/userRoutes');
const twoFactorRoutes = require('./src/routes/twoFactorRoutes');
const deviceRoutes = require('./src/routes/deviceRoutes');
const sessionRoutes = require('./src/routes/sessionRoutes');

const app = express();

// Connect Database
connectDB();

// Security Middlewares
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      scriptSrc: ["'self'"]
    }
  }
}));

// ✅ FIXED CORS (important for mobile login)
app.use(cors({
  origin: "*", // 🔥 allow all origins (dev)
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID', 'x-device-id'] // ✅ added device header
}));

// Body parsers
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(compression());

// Data sanitization
app.use(mongoSanitize());
app.use(hpp());

// Request logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// API Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/2fa', twoFactorRoutes);
app.use('/api/v1/devices', deviceRoutes);
app.use('/api/v1/sessions', sessionRoutes);

// Error handling
app.use(notFound);
app.use(globalErrorHandler);

const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, '0.0.0.0', () => { // ✅ allow network access
  logger.info(`🚀 Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
});

// Graceful shutdown
process.on('unhandledRejection', (err) => {
  logger.error('Unhandled Rejection:', err);
  server.close(() => process.exit(1));
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
  });
});

module.exports = app;