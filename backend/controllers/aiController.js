exports.detectThreat = async (req, res) => {

  const { activityScore } = req.body;

  let threat;

  if (activityScore > 0.8) threat = "HIGH";
  else if (activityScore > 0.5) threat = "MEDIUM";
  else threat = "LOW";

  res.json({
    threatLevel: threat,
    message: "AI behaviour analyzed",
  });
};