import sys
from collections import Counter

from parsers.manager import ParserManager
from detection_engine import run_detections
from incident.engine import IncidentEngine
from threat_intelligence.enricher import ThreatIntelligenceEnricher
from ai.soc_agent import AISOCAnalyst


def print_header():
    print("=" * 75)
    print("                    AI SECURITY LOG ANALYZER")
    print("=" * 75)


def print_separator():
    print("-" * 75)


def analyze_file(file_path):

    print_header()
    print()
    print(f"Log File       : {file_path}")

    # =========================================================
    # PARSER
    # =========================================================

    manager = ParserManager()

    try:
        parser_name, events = manager.parse_file(file_path)

    except FileNotFoundError:
        print()
        print("[ERROR] Log file does not exist.")
        print("=" * 75)
        return

    except ValueError as error:
        print()
        print(f"[ERROR] {error}")
        print("=" * 75)
        return

    except Exception as error:
        print()
        print(f"[ERROR] Unexpected parser error: {error}")
        print("=" * 75)
        return

    print(f"Detected Type  : {parser_name}")
    print(f"Total Events   : {len(events)}")

    # =========================================================
    # SEVERITY SUMMARY
    # =========================================================

    severity_counter = Counter()

    for event in events:
        severity = getattr(event, "severity", "INFO")
        severity_counter[severity] += 1

    print()
    print("Severity Summary")
    print_separator()

    severity_order = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]

    for severity in severity_order:
        print(
            f"{severity:<10}"
            f"{severity_counter.get(severity, 0)} events"
        )

    # =========================================================
    # SOURCE IP ACTIVITY
    # =========================================================

    ip_counter = Counter()

    for event in events:

        source_ip = getattr(
            event,
            "source_ip",
            None
        )

        if source_ip:
            ip_counter[source_ip] += 1

    print()
    print("Source IP Activity")
    print_separator()

    if ip_counter:

        for ip, count in ip_counter.most_common():

            print(
                f"{ip:<22}"
                f"{count} events"
            )

    else:

        print(
            "No source IP information found."
        )

    # =========================================================
    # USERNAME ACTIVITY
    # =========================================================

    username_counter = Counter()

    for event in events:

        username = getattr(
            event,
            "username",
            None
        )

        if username:
            username_counter[username] += 1

    print()
    print("Username Activity")
    print_separator()

    if username_counter:

        for username, count in username_counter.most_common():

            print(
                f"{username:<22}"
                f"{count} events"
            )

    else:

        print(
            "No username information found."
        )

    # =========================================================
    # EVENT TYPE ACTIVITY
    # =========================================================

    event_type_counter = Counter()

    for event in events:

        event_type = getattr(
            event,
            "event_type",
            "unknown"
        )

        event_type_counter[event_type] += 1

    print()
    print("Event Type Activity")
    print_separator()

    for event_type, count in event_type_counter.most_common():

        print(
            f"{event_type:<30}"
            f"{count} events"
        )

    # =========================================================
    # DETECTION ENGINE
    # =========================================================

    try:

        detections = run_detections(
            events
        )

    except Exception as error:

        print()
        print(
            "[ERROR] Detection engine failed: "
            f"{error}"
        )

        detections = []

    print()
    print("Detection Engine Results")
    print_separator()

    if not detections:

        print(
            "No suspicious activity detected."
        )

    else:

        for detection in detections:

            severity = detection.get(
                "severity",
                "INFO"
            )

            detection_type = detection.get(
                "type",
                "Unknown Detection"
            )

            description = detection.get(
                "description",
                "No description available."
            )

            source_ip = detection.get(
                "source_ip"
            )

            username = detection.get(
                "username"
            )

            count = detection.get(
                "count"
            )

            print()
            print(
                f"[{severity}] "
                f"{detection_type}"
            )

            print(
                f"    {description}"
            )

            if source_ip:

                print(
                    f"    Source IP : "
                    f"{source_ip}"
                )

            if username:

                print(
                    f"    Username   : "
                    f"{username}"
                )

            if count is not None:

                print(
                    f"    Count      : "
                    f"{count}"
                )

    # =========================================================
    # INCIDENT ENGINE
    # =========================================================

    try:

        incident_engine = IncidentEngine()

        incidents = incident_engine.create_incidents(
            detections
        )

    except Exception as error:

        print()
        print(
            "[ERROR] Incident engine failed: "
            f"{error}"
        )

        incidents = []

    # =========================================================
    # THREAT INTELLIGENCE
    # =========================================================

    threat_intel = ThreatIntelligenceEnricher()

    enriched_incidents = []

    for incident in incidents:

        try:

            enriched_incident = (
                threat_intel.enrich_incident(
                    incident
                )
            )

            enriched_incidents.append(
                enriched_incident
            )

        except Exception as error:

            print()
            print(
                "[WARNING] Threat intelligence "
                "enrichment failed for "
                f"{incident.get('source_ip')}: "
                f"{error}"
            )

            enriched_incidents.append(
                incident
            )

    incidents = enriched_incidents

    # =========================================================
    # SECURITY INCIDENTS
    # =========================================================

    print()
    print("Security Incidents")
    print_separator()

    if not incidents:

        print(
            "No security incidents created."
        )

    else:

        for incident in incidents:

            print()

            print(
                f"[{incident.get('severity', 'INFO')}] "
                f"{incident.get('incident_id', 'UNKNOWN')}"
            )

            print(
                f"    Source IP      : "
                f"{incident.get('source_ip', 'Unknown')}"
            )

            print(
                f"    Risk Score     : "
                f"{incident.get('risk_score', 0)}/100"
            )

            print(
                f"    Detections     : "
                f"{incident.get('detection_count', 0)}"
            )

            attack_types = incident.get(
                "attack_types",
                []
            )

            print(
                f"    Attack Types   : "
                f"{', '.join(attack_types)}"
            )

            print(
                f"    Status         : "
                f"{incident.get('status', 'UNKNOWN')}"
            )

            print(
                f"    Summary        : "
                f"{incident.get('summary', 'No summary')}"
            )

            # -------------------------------------------------
            # THREAT INTELLIGENCE
            # -------------------------------------------------

            intelligence = incident.get(
                "threat_intelligence"
            )

            if intelligence:

                print()
                print(
                    "    Threat Intelligence"
                )

                print(
                    f"        Classification : "
                    f"{intelligence.get('classification')}"
                )

                print(
                    f"        Reputation     : "
                    f"{intelligence.get('reputation')}"
                )

                print(
                    f"        Malicious      : "
                    f"{intelligence.get('malicious')}"
                )

                print(
                    f"        Confidence     : "
                    f"{intelligence.get('confidence')}%"
                )

                print(
                    f"        Provider       : "
                    f"{intelligence.get('provider')}"
                )

    # =========================================================
    # REAL AI SOC ANALYST
    # =========================================================

    print()
    print("AI SOC ANALYST")
    print_separator()

    ai_analyst = AISOCAnalyst()

    ai_assessments = []

    for incident in incidents:

        try:

            assessment = (
                ai_analyst.analyze_incident(
                    incident
                )
            )

            ai_assessments.append(
                assessment
            )

        except Exception as error:

            print()
            print(
                "[WARNING] AI SOC Analyst "
                f"failed: {error}"
            )

    if not ai_assessments:

        print(
            "No AI assessments generated."
        )

    else:

        for assessment in ai_assessments:

            print()

            print(
                f"Incident       : "
                f"{assessment.get('source_ip', 'Unknown')}"
            )

            print(
                f"Severity       : "
                f"{assessment.get('severity', 'INFO')}"
            )

            print(
                f"Risk Score     : "
                f"{assessment.get('risk_score', 0)}/100"
            )

            print(
                f"Provider       : "
                f"{assessment.get('provider', 'Unknown')}"
            )

            print(
                f"Model          : "
                f"{assessment.get('model', 'Unknown')}"
            )

            print()
            print("AI Analysis")
            print_separator()

            analysis = assessment.get(
                "analysis",
                "[No AI analysis returned.]"
            )

            print(analysis)

    # =========================================================
    # EVENT SEVERITY ANALYSIS
    # =========================================================

    print()
    print("Event Severity Analysis")
    print_separator()

    for event in events:

        severity = getattr(
            event,
            "severity",
            "INFO"
        )

        source_ip = getattr(
            event,
            "source_ip",
            None
        )

        username = getattr(
            event,
            "username",
            None
        )

        event_type = getattr(
            event,
            "event_type",
            "unknown"
        )

        message = getattr(
            event,
            "message",
            ""
        )

        source_ip_display = (
            source_ip
            if source_ip
            else "Unknown"
        )

        username_display = (
            username
            if username
            else "Unknown"
        )

        print(
            f"[{severity:<8}] "
            f"{source_ip_display:<18} "
            f"{username_display:<15} "
            f"{event_type:<22} "
            f"{message}"
        )

    # =========================================================
    # ANALYSIS STATISTICS
    # =========================================================

    unique_ips = set()
    unique_usernames = set()
    event_types = set()

    for event in events:

        source_ip = getattr(
            event,
            "source_ip",
            None
        )

        username = getattr(
            event,
            "username",
            None
        )

        event_type = getattr(
            event,
            "event_type",
            None
        )

        if source_ip:
            unique_ips.add(
                source_ip
            )

        if username:
            unique_usernames.add(
                username
            )

        if event_type:
            event_types.add(
                event_type
            )

    print()
    print("Analysis Statistics")
    print_separator()

    print(
        f"Total Events       : "
        f"{len(events)}"
    )

    print(
        f"Unique Source IPs  : "
        f"{len(unique_ips)}"
    )

    print(
        f"Unique Usernames   : "
        f"{len(unique_usernames)}"
    )

    print(
        f"Event Types        : "
        f"{len(event_types)}"
    )

    print(
        f"Detections         : "
        f"{len(detections)}"
    )

    print(
        f"Incidents          : "
        f"{len(incidents)}"
    )

    print()
    print("=" * 75)
    print("                     ANALYSIS COMPLETE")
    print("=" * 75)


def main():

    if len(sys.argv) != 2:

        print()
        print("Usage:")
        print(
            "    python3 analyzer.py "
            "<log_file>"
        )

        print()
        print("Example:")
        print(
            "    python3 analyzer.py "
            "sample_logs/suspicious.log"
        )

        sys.exit(1)

    file_path = sys.argv[1]

    analyze_file(
        file_path
    )


if __name__ == "__main__":
    main()
