const express = require('express');
const router = express.Router();
const c = require('../controllers/deviceController');
const { protect } = require('../middleware/authMiddleware');

router.use(protect);
router.get('/',           c.getSessions);
router.get('/history',    c.getLoginHistory);
router.delete('/:sessionId', c.revokeSession);

module.exports = router;
