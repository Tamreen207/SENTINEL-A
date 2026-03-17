const express = require("express");
const cors = require("cors");
require("dotenv").config();

const aiRoutes = require("./routes/aiRoutes");
const alertRoutes = require("./routes/alertRoutes");
const adminRoutes = require("./routes/adminRoutes");
const scanRoutes = require("./routes/scanRoutes");
const simulationRoutes = require("./routes/simulationRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const monitoringRoutes = require("./routes/monitoringRoutes");
const { scanMessage } = require("./controllers/scanController");
const connectDB = require("./config/db");
const { startFileIntegrityMonitor } = require("./services/fileIntegrityMonitor");

const app = express();

connectDB();
startFileIntegrityMonitor();

const frontendOrigin = process.env.FRONTEND_ORIGIN || "http://localhost:3000";

app.use(
  cors({
    origin: frontendOrigin,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);
app.use(express.json());

app.post("/check", scanMessage);

app.use(scanRoutes);
app.use(simulationRoutes);
app.use(dashboardRoutes);
app.use(monitoringRoutes);

app.use("/api/ai", aiRoutes);
app.use("/api/alerts", alertRoutes);
app.use("/api/admin", adminRoutes);
app.use("/alerts", alertRoutes);
app.use("/admin", adminRoutes);

app.get("/", (req, res) => {
  res.json({
    name: "Sentinel-A: AI Agent Cyber Shield",
    status: "Backend Running",
  });
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

const PORT = Number(process.env.PORT) || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});