const express = require("express");
const router = express.Router();
const { scanMessage } = require("../controllers/scanController");

router.post("/detect", scanMessage);

module.exports = router;