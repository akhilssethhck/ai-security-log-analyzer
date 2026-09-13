def build_incident_context(incident):
    """
    Build a compact evidence-only context for the local LLM.

    The LLM does not need the complete log file.
    It only needs the information required to explain
    the detected incident.
    """

    source_ip = incident.get("source_ip", "Unknown")
    severity = incident.get("severity", "Unknown")
    risk_score = incident.get("risk_score", 0)

    attack_types = incident.get("attack_types", [])
    detections = incident.get("detections", [])
    threat_intelligence = incident.get(
        "threat_intelligence",
        {}
    )

    lines = [
        f"Source IP: {source_ip}",
        f"Severity: {severity}",
        f"Risk Score: {risk_score}/100",
    ]

    if attack_types:
        lines.append(
            "Attack Types: "
            + ", ".join(
                str(item) for item in attack_types[:8]
            )
        )

    # Keep only the most important detections.
    for detection in detections[:8]:
        if not isinstance(detection, dict):
            continue

        detection_severity = detection.get(
            "severity",
            "UNKNOWN"
        )

        name = detection.get(
            "name",
            detection.get(
                "rule",
                detection.get(
                    "detection",
                    "Security Detection"
                )
            )
        )

        description = detection.get(
            "description",
            detection.get(
                "message",
                ""
            )
        )

        lines.append(
            f"[{detection_severity}] {name}: "
            f"{description}"
        )

    if threat_intelligence:
        classification = threat_intelligence.get(
            "classification"
        )

        reputation = threat_intelligence.get(
            "reputation"
        )

        if classification:
            lines.append(
                f"IP Classification: {classification}"
            )

        if reputation:
            lines.append(
                f"IP Reputation: {reputation}"
            )

    return "\n".join(lines)
