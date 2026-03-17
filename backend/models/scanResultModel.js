const mongoose = require("mongoose");

const scanResultSchema = new mongoose.Schema(
  {
    inputData: {
      type: String,
      required: true,
      trim: true,
    },
    inputType: {
      type: String,
      enum: ["message", "email", "url", "log"],
      default: "message",
    },
    detectedThreats: {
      type: [String],
      default: [],
    },
    highlightedKeywords: {
      type: [String],
      default: [],
    },
    explanation: {
      type: [String],
      default: [],
    },
    threatCategory: {
      type: String,
      default: "general threat",
      trim: true,
    },
    confidenceScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    actionTaken: {
      type: String,
      default: "Monitoring enabled",
      trim: true,
    },
    sourceIp: {
      type: String,
      default: "",
      trim: true,
    },
    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
    classification: {
      type: String,
      enum: ["Safe", "Suspicious", "High Risk"],
      required: true,
    },
    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: false,
  }
);

module.exports = mongoose.model("ScanResult", scanResultSchema);