const express = require('express');
const router = express.Router();
const deviceController = require('../controllers/deviceController');
const { protect } = require('../middleware/authMiddleware');

router.use(protect);
router.get('/', deviceController.getSessions);
router.get('/history', deviceController.getLoginHistory);
router.delete('/:sessionId', deviceController.revokeSession);

module.exports = router;
