function detectAnomaly(actions) {
  if (actions.includes("Delete Complaints")) {
    return {
      threat: true,
      risk: "High"
    };
  }

  return {
    threat: false,
    risk: "Low"
  };
}

module.exports = detectAnomaly;