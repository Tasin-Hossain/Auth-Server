const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { protect, authorize } = require('../middleware/authMiddleware');

router.use(protect);

router.patch('/profile', userController.updateProfile);
router.get('/security', userController.getSecurityOverview);
router.delete('/me', userController.deleteAccount);
router.get('/', authorize('admin', 'super_admin'), userController.getAllUsers);

module.exports = router;
