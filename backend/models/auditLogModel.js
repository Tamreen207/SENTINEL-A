const mongoose = require("mongoose");

const auditLogSchema = new mongoose.Schema({
  attackType: {
    type: String,
    required: true,
    trim: true,
  },
  actionTaken: {
    type: String,
    required: true,
    trim: true,
  },
  status: {
    type: String,
    enum: ["Detected", "Blocked", "Monitoring", "Resolved"],
    default: "Detected",
  },
  details: {
    type: String,
    default: "",
    trim: true,
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0,
  },
  sourceIp: {
    type: String,
    default: "",
    trim: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("AuditLog", auditLogSchema);
