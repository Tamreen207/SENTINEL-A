const ScanResult = require("../models/scanResultModel");
const Alert = require("../models/alertModel");
const AuditLog = require("../models/auditLogModel");

exports.getAllScans = async (_req, res) => {
	try {
		const scans = await ScanResult.find().sort({ timestamp: -1 }).limit(500).lean();
		res.json(scans);
	} catch (error) {
		res.status(500).json({ error: "Failed to fetch scans", details: error.message });
	}
};

exports.getAllAlerts = async (_req, res) => {
	try {
		const alerts = await Alert.find().sort({ timestamp: -1 }).limit(500).lean();
		res.json(alerts);
	} catch (error) {
		res.status(500).json({ error: "Failed to fetch admin alerts", details: error.message });
	}
};

exports.getHighRiskThreats = async (_req, res) => {
	try {
		const highRiskThreats = await ScanResult.find({ classification: "High Risk" })
			.sort({ timestamp: -1 })
			.limit(300)
			.lean();

		res.json(highRiskThreats);
	} catch (error) {
		res.status(500).json({ error: "Failed to fetch high risk threats", details: error.message });
	}
};

exports.getAuditTrail = async (_req, res) => {
	try {
		const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(500).lean();
		res.json(logs);
	} catch (error) {
		res.status(500).json({ error: "Failed to fetch audit logs", details: error.message });
	}
};
