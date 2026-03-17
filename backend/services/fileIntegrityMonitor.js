const { createIncident } = require("./incidentManager");

const monitoredFiles = [
  {
    fileName: "financial_data.csv",
    location: "Database Server",
    baselineHash: "sha256-financial-data-v1",
    currentHash: "sha256-financial-data-v1",
    status: "healthy",
    lastChecked: new Date(),
  },
  {
    fileName: "user_records.txt",
    location: "Database Server",
    baselineHash: "sha256-user-records-v1",
    currentHash: "sha256-user-records-v1",
    status: "healthy",
    lastChecked: new Date(),
  },
  {
    fileName: "security_logs.json",
    location: "Log Storage",
    baselineHash: "sha256-security-logs-v1",
    currentHash: "sha256-security-logs-v1",
    status: "healthy",
    lastChecked: new Date(),
  },
];

let monitorIntervalStarted = false;

const getMonitoredFiles = () =>
  monitoredFiles.map((file) => ({
    ...file,
    lastChecked: new Date(file.lastChecked),
  }));

const findFile = (fileName) => monitoredFiles.find((file) => file.fileName === fileName);

const ensureFile = (fileName, location) => {
  const existing = findFile(fileName);
  if (existing) return existing;

  const file = {
    fileName,
    location,
    baselineHash: `sha256-${fileName}-baseline`,
    currentHash: `sha256-${fileName}-baseline`,
    status: "healthy",
    lastChecked: new Date(),
  };

  monitoredFiles.push(file);
  return file;
};

const applyFileEvent = async ({ fileName, action, location, sourceIp = "198.51.100.27" }) => {
  const file = ensureFile(fileName, location);
  const normalizedAction = action.toLowerCase();
  file.lastChecked = new Date();

  if (normalizedAction === "deleted") {
    file.status = "deleted";
    file.currentHash = "missing";
  } else if (normalizedAction === "modified") {
    file.status = "modified";
    file.currentHash = `${file.currentHash}-modified-${Date.now()}`;
  } else if (normalizedAction === "replaced") {
    file.status = "replaced";
    file.currentHash = `sha256-replaced-${Date.now()}`;
  }

  const riskScore = normalizedAction === "deleted" ? 96 : normalizedAction === "replaced" ? 92 : 88;
  const alertType = normalizedAction === "deleted" ? "File Deletion" : normalizedAction === "replaced" ? "File Replacement" : "Unauthorized File Modification";

  const incident = await createIncident({
    alertType,
    attackLocation: location,
    message: `${alertType} detected by file integrity monitoring`,
    riskScore,
    sourceIp,
    sourceLocation: { city: "Frankfurt", country: "Germany", x: 52, y: 34 },
    fileName,
    threatCategory: "data tampering",
    confidenceScore: 91,
    metadata: {
      monitorType: "file-integrity",
      action: normalizedAction,
    },
  });

  return {
    file: { ...file },
    incident,
  };
};

const startFileIntegrityMonitor = () => {
  if (monitorIntervalStarted) return;
  monitorIntervalStarted = true;

  setInterval(() => {
    monitoredFiles.forEach((file) => {
      file.lastChecked = new Date();
    });
  }, 15000);
};

module.exports = {
  startFileIntegrityMonitor,
  getMonitoredFiles,
  applyFileEvent,
};
