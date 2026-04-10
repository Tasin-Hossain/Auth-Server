const express = require('express');
const router  = express.Router();
const { protect, authorize } = require('../middleware/authMiddleware');
const RiskLog = require('../models/RiskLog');
const { catchAsync } = require('../utils/errorUtils');

// @desc  Get my risk logs
// @route GET /api/v1/risk/me
router.get('/me', protect, catchAsync(async (req, res) => {
  const logs = await RiskLog.find({ userId: req.user.id })
    .sort({ timestamp: -1 })
    .limit(50)
    .lean();

  const stats = {
    total:       logs.length,
    aiUsed:      logs.filter(l => l.aiUsed).length,
    blocked:     logs.filter(l => l.action === 'blocked').length,
    alerted:     logs.filter(l => l.action === 'alerted').length,
    avgScore:    logs.length ? Math.round(logs.reduce((a, l) => a + l.finalScore, 0) / logs.length) : 0,
    geminiActive: !!process.env.GEMINI_API_KEY,
  };

  res.status(200).json({ success: true, data: { logs, stats } });
}));

// @desc  Admin: all risk logs
// @route GET /api/v1/risk/admin
router.get('/admin', protect, authorize('admin','super_admin'), catchAsync(async (req, res) => {
  const page  = parseInt(req.query.page)  || 1;
  const limit = parseInt(req.query.limit) || 30;
  const logs  = await RiskLog.find()
    .sort({ timestamp: -1 })
    .skip((page - 1) * limit)
    .limit(limit)
    .lean();
  const total = await RiskLog.countDocuments();
  res.status(200).json({ success: true, data: { logs, total, page, pages: Math.ceil(total / limit) } });
}));

module.exports = router;
