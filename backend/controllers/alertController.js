const Alert = require("../models/alertModel");

exports.getAlerts = async (_req, res) => {
	try {
		const alerts = await Alert.find().sort({ timestamp: -1 }).limit(200).lean();
		res.json(alerts);
	} catch (error) {
		res.status(500).json({ error: "Failed to fetch alerts", details: error.message });
	}
};
