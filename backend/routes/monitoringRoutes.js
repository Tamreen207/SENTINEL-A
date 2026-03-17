const express = require("express");
const router = express.Router();
const {
  getFileIntegrityStatus,
  analyzeBehavior,
  getAuditLogs,
} = require("../controllers/monitoringController");

router.get("/monitor/files", getFileIntegrityStatus);
router.post("/monitor/behavior", analyzeBehavior);
router.get("/audit-logs", getAuditLogs);

module.exports = router;
