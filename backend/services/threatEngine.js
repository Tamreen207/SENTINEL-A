const urlRegex = /(https?:\/\/[^\s]+)/gi;

const phishingKeywords = [
  "urgent",
  "bank",
  "verify",
  "account suspended",
  "security alert",
  "password",
  "otp",
  "confirm identity",
];

const fraudKeywords = [
  "lottery",
  "winner",
  "job offer",
  "crypto investment",
  "double your money",
  "claim reward",
  "wire money",
  "gift card",
];

const suspiciousCommandPatterns = [
  /rm\s+-rf/i,
  /truncate\s+-s\s+0/i,
  /del\s+\/f\s+\/q/i,
  /drop\s+table/i,
  /delete\s+from\s+\w+/i,
  /sudo\s+rm/i,
  /:(){:|:&};:/,
];

const logDeletionPatterns = [
  /rm\s+.*\/var\/log/i,
  /clear\s+event\s+log/i,
  /wevtutil\s+cl/i,
  /echo\s+""\s*>\s*.*\.log/i,
  /journalctl\s+--vacuum-time/i,
];

const suspiciousDomainPatterns = [
  /bit\.ly/i,
  /tinyurl\.com/i,
  /t\.co\//i,
  /free-[a-z0-9-]+\./i,
  /secure-[a-z0-9-]+\./i,
  /[a-z0-9-]+-verify\./i,
  /\d+\.\d+\.\d+\.\d+/i,
];

const malwareLinkPatterns = [/\.exe$/i, /\.bat$/i, /\/download\//i, /\/payload\//i];

const extractUrls = (inputText) => inputText.match(urlRegex) || [];

const findKeywordMatches = (inputText, keywords) => {
  const lower = inputText.toLowerCase();
  return keywords.filter((keyword) => lower.includes(keyword));
};

const findPatternMatches = (inputText, patterns, labels) =>
  patterns
    .map((pattern, index) => ({ pattern, label: labels?.[index] || pattern.source }))
    .filter(({ pattern }) => pattern.test(inputText))
    .map(({ label }) => label);

const scoreAndClassify = (signals) => {
  const score = Math.min(
    signals.phishing.length * 10 +
      signals.fraud.length * 11 +
      signals.maliciousUrls.length * 15 +
      signals.suspiciousCommands.length * 18 +
      signals.logDeletionAttempts.length * 22 +
      signals.dataManipulationSignals.length * 20,
    100
  );

  if (score <= 30) return { riskScore: score, classification: "Safe" };
  if (score <= 60) return { riskScore: score, classification: "Suspicious" };
  return { riskScore: score, classification: "High Risk" };
};

const buildExplanation = (signals) => {
  const reasons = [];

  if (signals.phishing.length) reasons.push("contains phishing-oriented language and urgency cues");
  if (signals.fraud.length) reasons.push("includes scam/fraud phrases frequently seen in social engineering");
  if (signals.maliciousUrls.length) reasons.push("contains suspicious or potentially malicious URLs");
  if (signals.suspiciousCommands.length) reasons.push("contains commands associated with destructive or unauthorized actions");
  if (signals.logDeletionAttempts.length) reasons.push("includes indicators of log tampering or deletion attempts");
  if (signals.dataManipulationSignals.length) reasons.push("shows potential unauthorized data modification attempts");

  return reasons.length ? reasons : ["no clear threat indicators were found"]; 
};

const dedupe = (values) => [...new Set(values)];

const inferThreatCategory = (signals) => {
  if (signals.suspiciousCommands.length || signals.logDeletionAttempts.length) {
    return "malware activity";
  }

  if (signals.dataManipulationSignals.length) {
    return "data tampering";
  }

  if (signals.phishing.length || signals.maliciousUrls.length) {
    return "phishing attack";
  }

  if (signals.fraud.length) {
    return "phishing attack";
  }

  return "general threat";
};

const calculateConfidenceScore = (signals) =>
  Math.min(
    35 +
      signals.phishing.length * 8 +
      signals.fraud.length * 7 +
      signals.maliciousUrls.length * 10 +
      signals.suspiciousCommands.length * 12 +
      signals.logDeletionAttempts.length * 12 +
      signals.dataManipulationSignals.length * 10,
    99
  );

const recommendResponse = (riskScore, threatCategory) => {
  if (riskScore >= 90) {
    if (threatCategory === "data tampering") return "IP address blocked";
    if (threatCategory === "malware activity") return "Suspicious process stopped";
    return "Threat source blocked";
  }

  if (riskScore >= 70) {
    if (threatCategory === "phishing attack") return "Sender domain blocked";
    return "Monitoring enabled";
  }

  return "Monitoring enabled";
};

const analyzeThreat = ({ inputData, inputType = "message" }) => {
  const text = String(inputData || "").trim();
  const urls = extractUrls(text);

  const phishing = findKeywordMatches(text, phishingKeywords);
  const fraud = findKeywordMatches(text, fraudKeywords);
  const suspiciousCommands = findPatternMatches(text, suspiciousCommandPatterns);
  const logDeletionAttempts = findPatternMatches(text, logDeletionPatterns);

  const dataManipulationSignals = findKeywordMatches(text, [
    "update users set",
    "drop database",
    "unauthorized change",
    "tampered",
    "modified records",
  ]);

  const maliciousUrls = urls.filter(
    (url) =>
      suspiciousDomainPatterns.some((pattern) => pattern.test(url)) ||
      malwareLinkPatterns.some((pattern) => pattern.test(url)) ||
      !url.startsWith("https://")
  );

  const detectedThreats = dedupe([
    ...phishing.map(() => "Phishing Detection"),
    ...fraud.map(() => "Fraud Message Detection"),
    ...maliciousUrls.map(() => "Malicious URL Detection"),
    ...suspiciousCommands.map(() => "Suspicious Command Detection"),
    ...logDeletionAttempts.map(() => "Log Deletion Attempt"),
    ...dataManipulationSignals.map(() => "Unauthorized Data Modification"),
  ]);

  const highlightedKeywords = dedupe([
    ...phishing,
    ...fraud,
    ...maliciousUrls,
    ...suspiciousCommands,
    ...logDeletionAttempts,
    ...dataManipulationSignals,
  ]);

  const signals = {
    phishing,
    fraud,
    maliciousUrls,
    suspiciousCommands,
    logDeletionAttempts,
    dataManipulationSignals,
  };

  const { riskScore, classification } = scoreAndClassify(signals);
  const explanation = buildExplanation(signals);
  const threatCategory = inferThreatCategory(signals);
  const confidenceScore = calculateConfidenceScore(signals);
  const actionTaken = recommendResponse(riskScore, threatCategory);

  return {
    inputType,
    inputData: text,
    riskScore,
    classification,
    detectedThreats,
    highlightedKeywords,
    explanation,
    threatCategory,
    confidenceScore,
    actionTaken,
    urls,
    signals,
  };
};

module.exports = {
  analyzeThreat,
};
