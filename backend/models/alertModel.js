const mongoose = require("mongoose");

const alertSchema = new mongoose.Schema({
	alertType: {
		type: String,
		required: true,
		trim: true,
	},
	severity: {
		type: String,
		enum: ["Low", "Medium", "High", "Critical"],
		required: true,
	},
	attackLocation: {
		type: String,
		required: true,
		trim: true,
	},
	message: {
		type: String,
		required: true,
		trim: true,
	},
	riskScore: {
		type: Number,
		min: 0,
		max: 100,
		default: 0,
	},
	fileName: {
		type: String,
		default: "",
		trim: true,
	},
	sourceIp: {
		type: String,
		default: "",
		trim: true,
	},
	sourceLocation: {
		city: {
			type: String,
			default: "",
			trim: true,
		},
		country: {
			type: String,
			default: "",
			trim: true,
		},
		x: {
			type: Number,
			default: 50,
		},
		y: {
			type: Number,
			default: 50,
		},
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
	status: {
		type: String,
		enum: ["Detected", "Blocked", "Monitoring", "Resolved"],
		default: "Detected",
	},
	channels: {
		type: [
			{
				channel: String,
				status: String,
				message: String,
			},
		],
		default: [],
	},
	metadata: {
		type: Object,
		default: {},
	},
	timestamp: {
		type: Date,
		default: Date.now,
	},
});

module.exports = mongoose.model("Alert", alertSchema);
