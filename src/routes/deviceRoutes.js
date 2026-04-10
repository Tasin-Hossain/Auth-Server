const express = require('express');
const router = express.Router();
const c = require('../controllers/deviceController');
const { protect } = require('../middleware/authMiddleware');

router.use(protect);
router.get('/',                       c.getDevices);
router.patch('/:deviceId/trust',      c.trustDevice);
router.patch('/:deviceId/untrust',    c.untrustDevice);
router.patch('/:deviceId/rename',     c.renameDevice);
router.delete('/:deviceId',           c.removeDevice);

module.exports = router;
