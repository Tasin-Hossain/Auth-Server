const express = require('express');
const router  = express.Router();
const { subscribe } = require('../controllers/sseController');
const { protect }   = require('../middleware/authMiddleware');

// Protected SSE endpoint — every logged-in device connects here
router.get('/', protect, subscribe);

module.exports = router;
