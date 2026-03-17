const express = require("express");
const router = express.Router();
const {
  getAllScans,
  getAllAlerts,
  getHighRiskThreats,
  getAuditTrail,
} = require("../controllers/adminController");

router.get("/scans", getAllScans);
router.get("/alerts", getAllAlerts);
router.get("/high-risk", getHighRiskThreats);
router.get("/audit-logs", getAuditTrail);

module.exports = router;