require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const cookieParser  = require('cookie-parser');
const compression   = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const connectDB = require('./src/config/database');
const logger    = require('./src/config/logger');
const { globalErrorHandler, notFound } = require('./src/middleware/errorMiddleware');

// Routes
const authRoutes      = require('./src/routes/authRoutes');
const userRoutes      = require('./src/routes/userRoutes');
const twoFactorRoutes = require('./src/routes/twoFactorRoutes');
const deviceRoutes    = require('./src/routes/deviceRoutes');
const sessionRoutes   = require('./src/routes/sessionRoutes');

const app = express();

// ★ Railway reverse proxy এর পেছনে থাকে — এটা না দিলে rate-limit crash করে
app.set('trust proxy', 1);

connectDB();

// Helmet
app.use(helmet({ crossOriginEmbedderPolicy: false, contentSecurityPolicy: false }));

// CORS
const allowedOrigins = (process.env.CLIENT_URL || 'http://localhost:5173')
  .split(',')
  .map((o) => o.trim());

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    logger.warn(`CORS blocked: ${origin} | allowed: ${allowedOrigins.join(', ')}`);
    callback(new Error('CORS not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID', 'x-device-id'],
  optionsSuccessStatus: 200,
};

app.options('*', cors(corsOptions));
app.use(cors(corsOptions));

// Body parsers
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(compression());
app.use(mongoSanitize());
app.use(hpp());

app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    allowedOrigins,
    env: process.env.NODE_ENV,
  });
});

// API Routes
app.use('/api/v1/auth',     authRoutes);
app.use('/api/v1/users',    userRoutes);
app.use('/api/v1/2fa',      twoFactorRoutes);
app.use('/api/v1/devices',  deviceRoutes);
app.use('/api/v1/sessions', sessionRoutes);

app.use(notFound);
app.use(globalErrorHandler);

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`🚀 Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
  logger.info(`✅ Allowed origins: ${allowedOrigins.join(', ')}`);
});

module.exports = app;
