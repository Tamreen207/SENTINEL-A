const AuditLog = require("../models/auditLogModel");
const { getMonitoredFiles } = require("../services/fileIntegrityMonitor");
const { createBehaviorIncident } = require("../services/behaviorMonitor");

exports.getFileIntegrityStatus = async (_req, res) => {
  try {
    res.json({ files: getMonitoredFiles() });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch monitored files", details: error.message });
  }
};

exports.analyzeBehavior = async (req, res) => {
  try {
    const result = await createBehaviorIncident(req.body || {});
    res.status(200).json(result);
  } catch (error) {
    res.status(500).json({ error: "Failed to analyze behavior", details: error.message });
  }
};

exports.getAuditLogs = async (_req, res) => {
  try {
    const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(500).lean();
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch audit logs", details: error.message });
  }
};
