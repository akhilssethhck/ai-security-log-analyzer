from collections import deque

from parsers.manager import ParserManager
from detection_engine import run_detections
from incident.engine import IncidentEngine
from threat_intelligence.enricher import ThreatIntelligenceEnricher
from realtime.log_monitor import LogMonitor


class RealtimeSecurityMonitor:
    """
    Real-time security monitoring pipeline.

    Log
      ↓
    Parser
      ↓
    SecurityEvent
      ↓
    Detection Engine
      ↓
    Incident Engine
      ↓
    Threat Intelligence
    """

    def __init__(self, log_file, poll_interval=0.5):
        self.log_file = log_file
        self.poll_interval = poll_interval

        self.parser_manager = ParserManager()
        self.incident_engine = IncidentEngine()
        self.threat_intel = ThreatIntelligenceEnricher()

        self.events = deque(maxlen=5000)

        self.detection_history = set()
        self.incident_history = set()
        self.ti_history = set()

        self.total_lines = 0
        self.parsed_events = 0
        self.unknown_lines = 0
        self.total_detections = 0
        self.total_incidents = 0
        self.total_ti_checks = 0

        self.monitor = LogMonitor(
            file_path=log_file,
            callback=self._process_line,
            poll_interval=poll_interval,
        )

    def start(self):
        print("=" * 60)
        print(" REAL-TIME SECURITY MONITOR")
        print("=" * 60)
        print(f"Log file: {self.log_file}")
        print(f"Poll interval: {self.poll_interval}s")
        print()
        print("Pipeline:")
        print("Log")
        print(" ↓")
        print("Parser Manager")
        print(" ↓")
        print("SecurityEvent")
        print(" ↓")
        print("Detection Engine")
        print(" ↓")
        print("Incident Engine")
        print(" ↓")
        print("Threat Intelligence")
        print()
        print("Waiting for new log events...")
        print("Press Ctrl+C to stop.")
        print("=" * 60)

        self.monitor.start()

    def stop(self):
        self.monitor.stop()

        print()
        print("=" * 60)
        print(" REAL-TIME MONITOR STOPPED")
        print("=" * 60)
        print(f"Lines received:  {self.total_lines}")
        print(f"Events parsed:   {self.parsed_events}")
        print(f"Unknown lines:   {self.unknown_lines}")
        print(f"Detections:      {self.total_detections}")
        print(f"Incidents:       {self.total_incidents}")
        print(f"TI checks:       {self.total_ti_checks}")
        print("=" * 60)

    def _process_line(self, line):
        self.total_lines += 1

        # ------------------------------------------
        # 1. Detect parser
        # ------------------------------------------

        parser = self.parser_manager.detect_line_parser(line)

        if parser is None:
            self.unknown_lines += 1

            print()
            print("[UNRECOGNIZED LOG]")
            print(line)

            return

        # ------------------------------------------
        # 2. Parse event
        # ------------------------------------------

        try:
            parsed_events = parser.parse([line])

        except Exception as error:
            print()
            print(f"[PARSER ERROR] {error}")
            return

        if not parsed_events:
            return

        # ------------------------------------------
        # 3. Store event
        # ------------------------------------------

        for event in parsed_events:
            self.events.append(event)
            self.parsed_events += 1

            self._display_event(
                event,
                parser.name
            )

            # --------------------------------------
            # 4. Detection Engine
            # --------------------------------------

            detections = self._run_detection_engine()

            # --------------------------------------
            # 5. Incident Engine
            # --------------------------------------

            if detections:
                self._run_incident_engine()

    def _run_detection_engine(self):
        events = list(self.events)

        if not events:
            return []

        try:
            detections = run_detections(events)

        except Exception as error:
            print()
            print(f"[DETECTION ERROR] {error}")
            return []

        new_detections = []

        for detection in detections:
            fingerprint = self._create_detection_fingerprint(
                detection
            )

            if fingerprint in self.detection_history:
                continue

            self.detection_history.add(fingerprint)

            self.total_detections += 1

            new_detections.append(detection)

            self._display_detection(
                detection
            )

        return new_detections

    def _run_incident_engine(self):
        """
        Rebuild the current incident state from the
        rolling event window.
        """

        try:
            all_detections = run_detections(
                list(self.events)
            )

        except Exception as error:
            print()
            print(
                f"[INCIDENT ERROR] "
                f"Could not rebuild detections: {error}"
            )
            return

        try:
            incidents = self.incident_engine.create_incidents(
                all_detections
            )

        except Exception as error:
            print()
            print(f"[INCIDENT ERROR] {error}")
            return

        for incident in incidents:

            incident_id = incident.get(
                "incident_id"
            )

            risk_score = incident.get(
                "risk_score",
                0
            )

            detection_count = incident.get(
                "detection_count",
                0
            )

            fingerprint = (
                incident_id,
                risk_score,
                detection_count,
            )

            if fingerprint in self.incident_history:
                continue

            self.incident_history.add(fingerprint)

            self.total_incidents += 1

            self._display_incident(
                incident
            )

            # --------------------------------------
            # Threat Intelligence
            # --------------------------------------

            self._run_threat_intelligence(
                incident
            )

    def _run_threat_intelligence(self, incident):
        source_ip = incident.get(
            "source_ip"
        )

        if not source_ip:
            return

        if source_ip in self.ti_history:
            return

        self.ti_history.add(source_ip)

        try:
            print()
            print("[THREAT INTELLIGENCE]")
            print("-" * 60)
            print(f"Checking IP: {source_ip}")

            result = self.threat_intel.enrich_ip(
                source_ip
            )

            self.total_ti_checks += 1

            classification = result.get(
                "classification",
                "UNKNOWN"
            )

            reputation = result.get(
                "reputation",
                "UNKNOWN"
            )

            malicious = result.get(
                "malicious"
            )

            confidence = result.get(
                "confidence",
                0
            )

            provider = result.get(
                "provider",
                "UNKNOWN"
            )

            print(
                f"Classification: {classification}"
            )

            print(
                f"Reputation:     {reputation}"
            )

            print(
                f"Malicious:      {malicious}"
            )

            print(
                f"Confidence:     {confidence}%"
            )

            print(
                f"Provider:       {provider}"
            )

            print("-" * 60)

        except Exception as error:
            print(
                f"[TI ERROR] {error}"
            )

    def _create_detection_fingerprint(self, detection):
        detection_type = detection.get(
            "type",
            "Unknown Detection"
        )

        source_ip = detection.get(
            "source_ip",
            "Unknown"
        )

        username = detection.get(
            "username",
            ""
        )

        description = detection.get(
            "description",
            ""
        )

        count = detection.get(
            "count",
            ""
        )

        return (
            detection_type,
            source_ip,
            username,
            description,
            str(count),
        )

    def _display_event(self, event, parser_name):
        source_ip = event.source_ip or "N/A"
        username = event.username or "N/A"
        severity = event.severity or "INFO"
        event_type = event.event_type or "unknown"

        print()
        print("-" * 60)
        print("[NEW SECURITY EVENT]")
        print("-" * 60)
        print(f"Parser:     {parser_name}")
        print(f"Type:       {event_type}")
        print(f"Severity:   {severity}")
        print(f"Source IP:  {source_ip}")
        print(f"Username:   {username}")
        print(f"Message:    {event.message}")
        print("-" * 60)

    def _display_detection(self, detection):
        detection_type = detection.get(
            "type",
            "Unknown Detection"
        )

        severity = detection.get(
            "severity",
            "INFO"
        )

        source_ip = detection.get(
            "source_ip",
            "Unknown"
        )

        description = detection.get(
            "description",
            ""
        )

        count = detection.get(
            "count"
        )

        print()
        print("!" * 60)
        print("[SECURITY DETECTION]")
        print("!" * 60)
        print(f"Detection:  {detection_type}")
        print(f"Severity:   {severity}")
        print(f"Source IP:  {source_ip}")

        if description:
            print(f"Details:    {description}")

        if count is not None:
            print(f"Count:      {count}")

        print("!" * 60)

    def _display_incident(self, incident):
        incident_id = incident.get(
            "incident_id",
            "UNKNOWN"
        )

        source_ip = incident.get(
            "source_ip",
            "Unknown"
        )

        severity = incident.get(
            "severity",
            "INFO"
        )

        risk_score = incident.get(
            "risk_score",
            0
        )

        attack_types = incident.get(
            "attack_types",
            []
        )

        print()
        print("#" * 60)
        print("[SECURITY INCIDENT]")
        print("#" * 60)
        print(f"Incident ID:  {incident_id}")
        print(f"Source IP:    {source_ip}")
        print(f"Severity:     {severity}")
        print(f"Risk Score:   {risk_score}/100")
        print(
            f"Attack Types: "
            f"{', '.join(attack_types) if attack_types else 'None'}"
        )
        print(
            f"Summary:      "
            f"{incident.get('summary', '')}"
        )
        print("#" * 60)

    def get_events(self):
        return list(self.events)

    def get_statistics(self):
        return {
            "log_file": self.log_file,
            "total_lines": self.total_lines,
            "parsed_events": self.parsed_events,
            "unknown_lines": self.unknown_lines,
            "total_detections": self.total_detections,
            "total_incidents": self.total_incidents,
            "total_ti_checks": self.total_ti_checks,
            "events_in_memory": len(self.events),
        }


def main():
    import argparse
    import time

    parser = argparse.ArgumentParser(
        description="Real-time Security Log Monitor"
    )

    parser.add_argument(
        "log_file",
        help="Path to the log file to monitor"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=0.5,
        help="Polling interval in seconds"
    )

    args = parser.parse_args()

    monitor = RealtimeSecurityMonitor(
        log_file=args.log_file,
        poll_interval=args.interval,
    )

    try:
        monitor.start()

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping monitor...")

    finally:
        monitor.stop()


if __name__ == "__main__":
    main()
