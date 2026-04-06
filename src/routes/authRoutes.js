const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect, loginLimiter, registerLimiter, passwordResetLimiter } = require('../middleware/authMiddleware');
const { validateRegister, validateLogin, validateForgotPassword, validateResetPassword, validate } = require('../middleware/validationMiddleware');

// Public routes
router.post('/register', registerLimiter, validateRegister, validate, authController.register);
router.post('/login', loginLimiter, validateLogin, validate, authController.login);
router.post('/refresh', authController.refreshToken);
router.get('/verify-email/:token', authController.verifyEmail);
router.post('/resend-verification', authController.resendVerification);
router.post('/forgot-password', passwordResetLimiter, validateForgotPassword, validate, authController.forgotPassword);
router.post('/reset-password/:token', validateResetPassword, validate, authController.resetPassword);

// Protected routes
router.use(protect);
router.get('/me', authController.getMe);
router.post('/logout', authController.logout);
router.post('/logout-all', authController.logoutAll);
router.post('/change-password', authController.changePassword);

module.exports = router;
