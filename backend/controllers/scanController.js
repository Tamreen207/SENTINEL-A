const ScanResult = require("../models/scanResultModel");
const { analyzeThreat } = require("../services/threatEngine");
const { createIncident } = require("../services/incidentManager");

exports.scanMessage = async (req, res) => {
  try {
    const inputData = req.body?.inputData || req.body?.text || req.body?.message;
    const inputType = req.body?.inputType || "message";
    const sourceIp = req.body?.sourceIp || req.ip || "198.51.100.17";

    if (!inputData || typeof inputData !== "string") {
      return res.status(400).json({
        error: "inputData is required and must be a string",
      });
    }

    const analysis = analyzeThreat({ inputData, inputType });

    const scanResult = await ScanResult.create({
      inputData: analysis.inputData,
      inputType: analysis.inputType,
      riskScore: analysis.riskScore,
      classification: analysis.classification,
      detectedThreats: analysis.detectedThreats,
      highlightedKeywords: analysis.highlightedKeywords,
      explanation: analysis.explanation,
      threatCategory: analysis.threatCategory,
      confidenceScore: analysis.confidenceScore,
      actionTaken: analysis.actionTaken,
      sourceIp,
      timestamp: new Date(),
    });

    let incident = null;

    if (analysis.classification !== "Safe") {
      incident = await createIncident({
        alertType: analysis.detectedThreats[0] || "General Threat",
        attackLocation:
          analysis.inputType === "url"
            ? "URL Gateway"
            : analysis.inputType === "email"
              ? "Email Security"
              : analysis.inputType === "log"
                ? "Log Monitor"
                : "Message Channel",
        message: `Threat detected: ${analysis.detectedThreats.join(", ") || "Suspicious activity"}`,
        riskScore: analysis.riskScore,
          sourceIp,
          sourceLocation: { city: "New Delhi", country: "India", x: 74, y: 46 },
          threatCategory: analysis.threatCategory,
          confidenceScore: analysis.confidenceScore,
          metadata: {
            inputType: analysis.inputType,
            highlightedKeywords: analysis.highlightedKeywords,
          },
      });
    }

    return res.status(201).json({
      id: scanResult._id,
      classification: analysis.classification,
      riskScore: analysis.riskScore,
      detectedThreats: analysis.detectedThreats,
      explanation: analysis.explanation,
      highlightedKeywords: analysis.highlightedKeywords,
      threatCategory: analysis.threatCategory,
      confidenceScore: analysis.confidenceScore,
      actionTaken: analysis.actionTaken,
      notifications: incident?.alert?.channels || [],
      timestamp: scanResult.timestamp,
    });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to process scan request",
      details: error.message,
    });
  }
};

exports.getAlerts = async (_req, res) => {
  try {
    const alerts = await ScanResult.find({
      classification: { $in: ["Suspicious", "High Risk"] },
    })
      .sort({ timestamp: -1 })
      .limit(100)
      .lean();

    return res.json(alerts);
  } catch (error) {
    return res.status(500).json({
      error: "Failed to fetch alerts",
      details: error.message,
    });
  }
};

exports.getHistory = async (_req, res) => {
  try {
    const history = await ScanResult.find().sort({ timestamp: -1 }).limit(500).lean();
    return res.json(history);
  } catch (error) {
    return res.status(500).json({
      error: "Failed to fetch scan history",
      details: error.message,
    });
  }
};