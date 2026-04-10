const mongoose = require('mongoose');

// প্রতিটা login attempt এর risk analysis এখানে log হয়
const riskLogSchema = new mongoose.Schema({
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  email:      String,
  timestamp:  { type: Date, default: Date.now, index: true },

  // Request info
  ip:       String,
  location: String,
  browser:  String,
  os:       String,
  deviceId: String,

  // Heuristic scores
  heuristicScore: { type: Number, default: 0 },
  heuristicFlags: [String],

  // AI score
  aiUsed:   { type: Boolean, default: false },
  aiScore:  { type: Number, default: 0 },
  aiModel:  { type: String, default: '' }, // 'gemini-2.0-flash' or ''

  // Final result
  finalScore: { type: Number, default: 0 },
  riskLevel:  { type: String, enum: ['low','medium','high','critical'], default: 'low' },

  // Action taken
  action:    { type: String, enum: ['allowed','blocked','alerted','2fa_required'], default: 'allowed' },
  loginSuccess: Boolean,
}, {
  timestamps: false,
  versionKey: false,
});

// 30 দিন পরে auto-delete
riskLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });

module.exports = mongoose.model('RiskLog', riskLogSchema);
