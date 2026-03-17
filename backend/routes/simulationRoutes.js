const express = require("express");
const router = express.Router();
const {
  simulatePhishing,
  simulateDataAttack,
  simulateLogDelete,
  simulateCommandAttack,
  simulateFileDeletion,
  simulateDataTampering,
  simulateUnauthorizedLogin,
  simulateMalwareExecution,
} = require("../controllers/simulationController");

router.post("/simulate/phishing", simulatePhishing);
router.post("/simulate/data-attack", simulateDataAttack);
router.post("/simulate/log-delete", simulateLogDelete);
router.post("/simulate/command-attack", simulateCommandAttack);
router.post("/simulate/file-delete", simulateFileDeletion);
router.post("/simulate/data-tampering", simulateDataTampering);
router.post("/simulate/unauthorized-login", simulateUnauthorizedLogin);
router.post("/simulate/malware-execution", simulateMalwareExecution);

module.exports = router;
