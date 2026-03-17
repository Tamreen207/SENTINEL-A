const Alert = require("../models/alertModel");
const AuditLog = require("../models/auditLogModel");

const pickSeverity = (riskScore) => {
  if (riskScore >= 90) return "Critical";
  if (riskScore >= 70) return "High";
  if (riskScore >= 40) return "Medium";
  return "Low";
};

const classifyResponseAction = ({ alertType, riskScore }) => {
  const lowerType = String(alertType).toLowerCase();

  if (lowerType.includes("login") || lowerType.includes("brute force")) {
    return riskScore >= 70 ? "User account locked" : "Login attempt rate-limited";
  }

  if (lowerType.includes("malware") || lowerType.includes("command")) {
    return riskScore >= 70 ? "Suspicious process stopped" : "Process flagged for review";
  }

  if (lowerType.includes("file") || lowerType.includes("data tampering")) {
    return riskScore >= 70 ? "IP address blocked" : "File quarantined for review";
  }

  if (lowerType.includes("phishing")) {
    return riskScore >= 70 ? "Sender domain blocked" : "Message quarantined";
  }

  return riskScore >= 70 ? "Threat source blocked" : "Monitoring enabled";
};

const buildChannels = ({ alertType, riskScore }) => [
  {
    channel: "dashboard",
    status: "sent",
    message: `Dashboard notification issued for ${alertType}`,
  },
  {
    channel: "email",
    status: "simulated",
    message: `Email alert simulation: ${alertType} (${riskScore})`,
  },
  {
    channel: "telegram",
    status: "simulated",
    message: `Telegram alert simulation: ${alertType} (${riskScore})`,
  },
];

const createIncident = async ({
  alertType,
  attackLocation,
  message,
  riskScore,
  sourceIp = "203.0.113.18",
  sourceLocation = { city: "Singapore", country: "Singapore", x: 72, y: 62 },
  fileName = "",
  threatCategory = "general threat",
  confidenceScore = 80,
  metadata = {},
}) => {
  const severity = pickSeverity(riskScore);
  const actionTaken = classifyResponseAction({ alertType, riskScore });
  const status = riskScore >= 70 ? "Blocked" : "Detected";
  const channels = buildChannels({ alertType, riskScore });
  const timestamp = new Date();

  const alert = await Alert.create({
    alertType,
    severity,
    attackLocation,
    message,
    riskScore,
    timestamp,
    fileName,
    sourceIp,
    sourceLocation,
    threatCategory,
    confidenceScore,
    actionTaken,
    channels,
    status,
    metadata,
  });

  const auditLog = await AuditLog.create({
    attackType: alertType,
    actionTaken,
    status,
    details: `${message}${fileName ? ` | file: ${fileName}` : ""}`,
    riskScore,
    sourceIp,
    timestamp,
  });

  return { alert, auditLog };
};

module.exports = {
  createIncident,
  pickSeverity,
  classifyResponseAction,
};
