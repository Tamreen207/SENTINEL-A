const ScanResult = require("../models/scanResultModel");
const Alert = require("../models/alertModel");
const AuditLog = require("../models/auditLogModel");
const { getMonitoredFiles } = require("../services/fileIntegrityMonitor");

exports.getDashboard = async (_req, res) => {
  try {
    const [
      totalScans,
      threatsDetected,
      safeCount,
      suspiciousCount,
      highRiskCount,
      recentAlerts,
      totalAttacksDetected,
      filesModified,
      suspiciousLoginAttempts,
      activeThreats,
      auditLogs,
      attackSources,
    ] =
      await Promise.all([
        ScanResult.countDocuments(),
        ScanResult.countDocuments({ classification: { $in: ["Suspicious", "High Risk"] } }),
        ScanResult.countDocuments({ classification: "Safe" }),
        ScanResult.countDocuments({ classification: "Suspicious" }),
        ScanResult.countDocuments({ classification: "High Risk" }),
        Alert.find().sort({ timestamp: -1 }).limit(10).lean(),
        Alert.countDocuments(),
        Alert.countDocuments({
          $or: [
            { alertType: /file/i },
            { threatCategory: "data tampering" },
          ],
        }),
        Alert.countDocuments({ alertType: /login/i }),
        Alert.countDocuments({ status: { $in: ["Detected", "Blocked", "Monitoring"] } }),
        AuditLog.find().sort({ timestamp: -1 }).limit(12).lean(),
        Alert.find({ sourceIp: { $ne: "" } })
          .sort({ timestamp: -1 })
          .limit(8)
          .lean(),
      ]);

    const timelineAgg = await ScanResult.aggregate([
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$timestamp" },
          },
          scans: { $sum: 1 },
          threats: {
            $sum: {
              $cond: [{ $in: ["$classification", ["Suspicious", "High Risk"]] }, 1, 0],
            },
          },
        },
      },
      { $sort: { _id: 1 } },
      { $limit: 14 },
    ]);

    res.json({
      totalScans,
      threatsDetected,
      widgets: {
        totalAttacksDetected,
        filesModified,
        suspiciousLoginAttempts,
        systemHealthStatus: activeThreats > 5 ? "Degraded" : "Healthy",
        activeThreats,
      },
      distribution: {
        safe: safeCount,
        suspicious: suspiciousCount,
        highRisk: highRiskCount,
      },
      monitoredFiles: getMonitoredFiles(),
      attackTimeline: timelineAgg.map((entry) => ({
        date: entry._id,
        scans: entry.scans,
        threats: entry.threats,
      })),
      attackSources: attackSources.map((entry) => ({
        _id: entry._id,
        sourceIp: entry.sourceIp,
        city: entry.sourceLocation?.city || "Unknown",
        country: entry.sourceLocation?.country || "Unknown",
        x: entry.sourceLocation?.x ?? 50,
        y: entry.sourceLocation?.y ?? 50,
        alertType: entry.alertType,
        riskScore: entry.riskScore,
      })),
      auditSummary: auditLogs,
      recentAlerts,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to load dashboard", details: error.message });
  }
};
