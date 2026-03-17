const express = require("express");
const router = express.Router();
const { scanMessage, getHistory } = require("../controllers/scanController");

router.post("/scan", scanMessage);
router.get("/scans", getHistory);

module.exports = router;
