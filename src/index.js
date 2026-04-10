require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const cookieParser  = require('cookie-parser');
const compression   = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const hpp           = require('hpp');
const connectDB     = require('./config/database');
const logger        = require('./config/logger');
const { globalErrorHandler, notFound } = require('./middleware/errorMiddleware');

// Routes
const authRoutes      = require('./routes/authRoutes');
const userRoutes      = require('./routes/userRoutes');
const twoFactorRoutes = require('./routes/twoFactorRoutes');
const deviceRoutes    = require('./routes/deviceRoutes');
const sessionRoutes   = require('./routes/sessionRoutes');
const riskRoutes      = require('./routes/riskRoutes');

const app = express();

// Railway/Render reverse proxy fix
app.set('trust proxy', 1);

connectDB();

app.use(helmet({ crossOriginEmbedderPolicy: false, contentSecurityPolicy: false }));

// CORS
const allowedOrigins = (process.env.CLIENT_URL || 'http://localhost:5173').split(',').map(o => o.trim());

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    logger.warn(`CORS blocked: ${origin}`);
    cb(new Error('CORS not allowed'));
  },
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Tenant-ID','x-device-id'],
  optionsSuccessStatus: 200,
};

app.options('*', cors(corsOptions));
app.use(cors(corsOptions));

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

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString(), allowedOrigins, env: process.env.NODE_ENV });
});

app.use('/api/v1/auth',     authRoutes);
app.use('/api/v1/users',    userRoutes);
app.use('/api/v1/2fa',      twoFactorRoutes);
app.use('/api/v1/devices',  deviceRoutes);
app.use('/api/v1/sessions', sessionRoutes);
app.use('/api/v1/risk',     riskRoutes);

app.use(notFound);
app.use(globalErrorHandler);

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`🚀 Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
  logger.info(`✅ Allowed origins: ${allowedOrigins.join(', ')}`);
});

module.exports = app;
