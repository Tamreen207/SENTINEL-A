def detect_anomaly(actions):

    if "delete_complaints" in actions:
        return {
            "threat": True,
            "risk": "High"
        }

    return {
        "threat": False,
        "risk": "Low"
    }