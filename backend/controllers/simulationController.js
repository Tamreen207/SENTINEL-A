const { createIncident } = require("../services/incidentManager");
const { applyFileEvent } = require("../services/fileIntegrityMonitor");
const { createBehaviorIncident } = require("../services/behaviorMonitor");

const createSimulationResponse = async ({
  alertType,
  attackLocation,
  message,
  originalData,
  attackedData,
  riskScore,
  fileName = "",
  threatCategory = "general threat",
  confidenceScore = 84,
  sourceLocation = { city: "Warsaw", country: "Poland", x: 56, y: 38 },
}) => {
  const { alert } = await createIncident({
    alertType,
    attackLocation,
    message,
    riskScore,
    fileName,
    threatCategory,
    confidenceScore,
    sourceLocation,
  });

  return {
    success: true,
    alert,
    simulation: {
      originalData,
      attackedData,
      fileName,
      timestamp: alert.timestamp,
    },
  };
};

exports.simulatePhishing = async (_req, res) => {
  try {
    const payload = await createSimulationResponse({
      alertType: "Phishing Attack",
      attackLocation: "Email Gateway",
      message: "Simulated phishing campaign detected targeting banking credentials.",
      originalData: "Payment Verification: Pending",
      attackedData: "Payment Verification: Please verify OTP immediately",
      riskScore: 87,
      threatCategory: "phishing attack",
      confidenceScore: 92,
      sourceLocation: { city: "Manila", country: "Philippines", x: 82, y: 58 },
    });

    res.status(200).json(payload);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.simulateDataAttack = async (_req, res) => {
  try {
    const payload = await createSimulationResponse({
      alertType: "Data Manipulation",
      attackLocation: "Database Layer",
      message: "Unauthorized data tampering simulation triggered.",
      originalData: "Server Status: OK",
      attackedData: "Server Status: HACKED",
      riskScore: 95,
      fileName: "financial_data.csv",
      threatCategory: "data tampering",
      confidenceScore: 91,
      sourceLocation: { city: "Berlin", country: "Germany", x: 53, y: 35 },
    });

    res.status(200).json(payload);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.simulateLogDelete = async (_req, res) => {
  try {
    const payload = await createSimulationResponse({
      alertType: "Log Deletion Attempt",
      attackLocation: "System Logs",
      message: "Critical log deletion attempt simulation detected.",
      originalData: "auth.log entries: 1241",
      attackedData: "auth.log entries: 0",
      riskScore: 94,
      fileName: "auth.log",
      threatCategory: "malware activity",
      confidenceScore: 89,
      sourceLocation: { city: "Amsterdam", country: "Netherlands", x: 50, y: 32 },
    });

    res.status(200).json(payload);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.simulateCommandAttack = async (_req, res) => {
  try {
    const payload = await createSimulationResponse({
      alertType: "Command Injection",
      attackLocation: "Shell Executor",
      message: "Suspicious command execution simulation detected.",
      originalData: "Executed Command: ls -la",
      attackedData: "Executed Command: rm -rf / --no-preserve-root",
      riskScore: 93,
      threatCategory: "malware activity",
      confidenceScore: 94,
      sourceLocation: { city: "Seoul", country: "South Korea", x: 85, y: 42 },
    });

    res.status(200).json(payload);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.simulateFileDeletion = async (_req, res) => {
  try {
    const fileEvent = await applyFileEvent({
      fileName: "user_records.txt",
      action: "deleted",
      location: "Database Server",
    });

    res.status(200).json({
      success: true,
      alert: fileEvent.incident.alert,
      simulation: {
        originalData: "Original file: user_records.txt",
        attackedData: "After attack: File deleted",
        fileName: "user_records.txt",
        timestamp: fileEvent.incident.alert.timestamp,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.simulateDataTampering = async (_req, res) => {
  try {
    const fileEvent = await applyFileEvent({
      fileName: "financial_data.csv",
      action: "modified",
      location: "Server Storage",
    });

    res.status(200).json({
      success: true,
      alert: fileEvent.incident.alert,
      simulation: {
        originalData: "Quarterly Revenue: 4,200,000",
        attackedData: "Quarterly Revenue: 9,900,000",
        fileName: "financial_data.csv",
        timestamp: fileEvent.incident.alert.timestamp,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.simulateUnauthorizedLogin = async (_req, res) => {
  try {
    const result = await createBehaviorIncident({
      username: "ops-admin",
      loginHour: 2,
      filesAccessed: 24,
      loginAttempts: 6,
      unknownDevice: true,
      sourceIp: "91.132.44.18",
      location: { city: "Moscow", country: "Russia", x: 63, y: 28 },
    });

    res.status(200).json({
      success: true,
      alert: result.alert,
      simulation: {
        originalData: "Login Status: Normal authenticated session",
        attackedData: "Login Status: Unauthorized login attempts detected",
        timestamp: result.alert.timestamp,
      },
      behavior: result.analysis,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.simulateMalwareExecution = async (_req, res) => {
  try {
    const payload = await createSimulationResponse({
      alertType: "Malware Execution",
      attackLocation: "Endpoint Runtime",
      message: "Malware execution simulation detected and process terminated.",
      originalData: "Process: reports-generator.exe",
      attackedData: "Process: ransomware-loader.exe blocked",
      riskScore: 97,
      fileName: "payload.exe",
      threatCategory: "malware activity",
      confidenceScore: 96,
      sourceLocation: { city: "São Paulo", country: "Brazil", x: 34, y: 74 },
    });

    res.status(200).json(payload);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};
