const { createIncident } = require("./incidentManager");

const analyzeBehaviorEvent = ({
  username = "unknown-user",
  loginHour = 2,
  filesAccessed = 0,
  loginAttempts = 1,
  unknownDevice = false,
  sourceIp = "185.193.88.10",
  location = { city: "Bucharest", country: "Romania", x: 58, y: 42 },
}) => {
  const reasons = [];
  let riskScore = 10;

  if (loginHour < 6 || loginHour > 22) {
    reasons.push("login at unusual time");
    riskScore += 25;
  }

  if (unknownDevice) {
    reasons.push("unknown device login");
    riskScore = Math.max(riskScore, 40);
  }

  if (loginAttempts >= 4) {
    reasons.push("repeated login attempts");
    riskScore = Math.max(riskScore, 75);
  }

  if (filesAccessed >= 20) {
    reasons.push("accessing too many files");
    riskScore += 20;
  }

  riskScore = Math.min(riskScore, 100);
  const isAbnormal = reasons.length > 0;
  const classification = riskScore >= 61 ? "High Risk" : riskScore >= 31 ? "Suspicious" : "Safe";

  return {
    username,
    riskScore,
    classification,
    isAbnormal,
    reasons,
    threatCategory: loginAttempts >= 4 ? "brute force attack" : "insider threat",
    confidenceScore: loginAttempts >= 4 ? 93 : 85,
    sourceIp,
    location,
  };
};

const createBehaviorIncident = async (payload) => {
  const analysis = analyzeBehaviorEvent(payload);

  if (!analysis.isAbnormal) {
    return { analysis, alert: null, auditLog: null };
  }

  const incident = await createIncident({
    alertType: analysis.threatCategory === "brute force attack" ? "Suspicious Login Attempt" : "Abnormal User Activity",
    attackLocation: "Identity Access Management",
    message: `Possible insider threat detected for ${analysis.username}: ${analysis.reasons.join(", ")}`,
    riskScore: analysis.riskScore,
    sourceIp: analysis.sourceIp,
    sourceLocation: analysis.location,
    threatCategory: analysis.threatCategory,
    confidenceScore: analysis.confidenceScore,
    metadata: {
      username: analysis.username,
      reasons: analysis.reasons,
    },
  });

  return { analysis, ...incident };
};

module.exports = {
  analyzeBehaviorEvent,
  createBehaviorIncident,
};
