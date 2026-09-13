from collections import defaultdict


class IncidentEngine:
    """
    Converts individual security detections into
    structured security incidents.

    Correlation detections are excluded from the list
    of underlying attack behaviors because correlation
    is an incident-level conclusion.
    """

    SEVERITY_SCORES = {
        "INFO": 5,
        "LOW": 15,
        "MEDIUM": 35,
        "HIGH": 60,
        "CRITICAL": 90,
    }

    def __init__(self):
        pass

    # ========================================================
    # CREATE INCIDENTS
    # ========================================================

    def create_incidents(self, detections):
        """
        Group detections by source IP and create incidents.
        """

        incidents_by_ip = defaultdict(list)

        for detection in detections:

            source_ip = detection.get("source_ip")

            if not source_ip:
                continue

            incidents_by_ip[source_ip].append(detection)

        incidents = []

        for source_ip, ip_detections in incidents_by_ip.items():

            incident = self._build_incident(
                source_ip,
                ip_detections
            )

            incidents.append(incident)

        # Highest-risk incidents first
        incidents.sort(
            key=lambda incident: incident["risk_score"],
            reverse=True
        )

        return incidents

    # ========================================================
    # BUILD INCIDENT
    # ========================================================

    def _build_incident(
        self,
        source_ip,
        detections
    ):

        attack_types = []

        highest_severity = "INFO"
        risk_score = 0

        underlying_detection_count = 0

        for detection in detections:

            detection_type = detection.get(
                "type",
                "Unknown Detection"
            )

            # ------------------------------------------------
            # Correlation is NOT an attack type.
            #
            # It is the conclusion that multiple detections
            # belong together.
            # ------------------------------------------------

            if detection_type == "Correlated Suspicious Activity":
                continue

            underlying_detection_count += 1

            if detection_type not in attack_types:
                attack_types.append(
                    detection_type
                )

            severity = detection.get(
                "severity",
                "INFO"
            ).upper()

            severity_score = self.SEVERITY_SCORES.get(
                severity,
                5
            )

            if severity_score > risk_score:
                risk_score = severity_score

            if self._severity_rank(
                severity
            ) > self._severity_rank(
                highest_severity
            ):
                highest_severity = severity

        # ====================================================
        # CORRELATION / BEHAVIOR SCORE
        # ====================================================

        behavior_count = len(attack_types)

        # Multiple different behaviors indicate
        # a more significant security incident.
        if behavior_count >= 2:
            risk_score += 10

        if behavior_count >= 4:
            risk_score += 10

        if behavior_count >= 6:
            risk_score += 10

        # Never exceed 100.
        risk_score = min(
            risk_score,
            100
        )

        # ====================================================
        # FINAL INCIDENT SEVERITY
        # ====================================================

        if risk_score >= 90:

            incident_severity = "CRITICAL"

        elif risk_score >= 70:

            incident_severity = "HIGH"

        elif risk_score >= 40:

            incident_severity = "MEDIUM"

        else:

            incident_severity = "LOW"

        # ====================================================
        # CREATE INCIDENT
        # ====================================================

        return {
            "incident_id":
                self._generate_incident_id(
                    source_ip
                ),

            "source_ip":
                source_ip,

            "severity":
                incident_severity,

            "risk_score":
                risk_score,

            "detection_count":
                underlying_detection_count,

            "attack_types":
                attack_types,

            "detections":
                detections,

            "status":
                "OPEN",

            "summary":
                self._generate_summary(
                    source_ip,
                    incident_severity,
                    attack_types
                ),
        }

    # ========================================================
    # INCIDENT ID
    # ========================================================

    def _generate_incident_id(
        self,
        source_ip
    ):

        clean_ip = source_ip.replace(
            ".",
            "-"
        )

        return f"INC-{clean_ip}"

    # ========================================================
    # SEVERITY RANKING
    # ========================================================

    def _severity_rank(
        self,
        severity
    ):

        ranks = {
            "INFO": 1,
            "LOW": 2,
            "MEDIUM": 3,
            "HIGH": 4,
            "CRITICAL": 5,
        }

        return ranks.get(
            severity.upper(),
            1
        )

    # ========================================================
    # INCIDENT SUMMARY
    # ========================================================

    def _generate_summary(
        self,
        source_ip,
        severity,
        attack_types
    ):

        if not attack_types:

            return (
                f"Suspicious activity detected "
                f"from {source_ip}."
            )

        if len(attack_types) == 1:

            return (
                f"{severity} security activity "
                f"detected from {source_ip}: "
                f"{attack_types[0]}."
            )

        return (
            f"{severity} correlated security incident "
            f"detected from {source_ip}. "
            f"Multiple attack behaviors were observed: "
            f"{', '.join(attack_types)}."
        )


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def create_incidents(detections):
    """
    Convenience function for creating incidents.
    """

    engine = IncidentEngine()

    return engine.create_incidents(
        detections
    )
