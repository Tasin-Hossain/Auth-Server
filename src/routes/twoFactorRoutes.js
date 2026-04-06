const express = require('express');
const router = express.Router();
const twoFactorController = require('../controllers/twoFactorController');
const { protect } = require('../middleware/authMiddleware');

// Public - verify during login (uses tempToken)
router.post('/verify', twoFactorController.verify2FA);

// Protected
router.use(protect);
router.post('/setup', twoFactorController.setup2FA);
router.post('/enable', twoFactorController.enable2FA);
router.post('/disable', twoFactorController.disable2FA);
router.post('/backup-codes/regenerate', twoFactorController.regenerateBackupCodes);

module.exports = router;
