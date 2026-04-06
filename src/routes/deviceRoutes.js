const express = require('express');
const router = express.Router();
const deviceController = require('../controllers/deviceController');
const { protect } = require('../middleware/authMiddleware');

router.use(protect);
router.get('/', deviceController.getDevices);
router.patch('/:deviceId/trust', deviceController.trustDevice);
router.patch('/:deviceId/rename', deviceController.renameDevice);
router.delete('/:deviceId', deviceController.removeDevice);

module.exports = router;
