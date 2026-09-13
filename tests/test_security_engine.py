import unittest

from event_schema import SecurityEvent
from detection_engine import (
    detect_repeated_auth_failures,
    detect_privileged_accounts,
    detect_username_enumeration,
    detect_port_scanning,
    detect_firewall_blocks,
    detect_web_scanning,
    detect_sql_injection,
    detect_xss,
    detect_path_traversal,
    detect_command_injection,
    detect_sensitive_paths,
    detect_suspicious_user_agents,
    detect_http_error_spike,
    run_detections,
)
from incident.engine import IncidentEngine


class SecurityEngineTests(unittest.TestCase):

    def make_event(
        self,
        event_type="authentication_failure",
        source_ip="192.168.1.100",
        username=None,
        destination_port=None,
        message="Failed password authentication",
        source="ssh",
        metadata=None,
    ):
        return SecurityEvent(
            source=source,
            event_type=event_type,
            severity="MEDIUM",
            source_ip=source_ip,
            destination_port=destination_port,
            username=username,
            message=message,
            raw_log=message,
            metadata=metadata or {},
        )

    # ---------------------------------------------------------
    # AUTHENTICATION
    # ---------------------------------------------------------

    def test_repeated_authentication_failures(self):

        events = [
            self.make_event(
                username="testuser",
                message="Failed password for testuser from 192.168.1.100",
            )
            for _ in range(5)
        ]

        detections = detect_repeated_auth_failures(
            events,
            threshold=5,
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Repeated Authentication Failures",
        )

    def test_privileged_account_detection(self):

        events = [
            self.make_event(
                username="root",
                message="Failed password for root from 192.168.1.100",
            )
        ]

        detections = detect_privileged_accounts(
            events
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Privileged Account Targeting",
        )

    def test_username_enumeration(self):

        events = [
            self.make_event(
                username="admin",
            ),
            self.make_event(
                username="root",
            ),
            self.make_event(
                username="administrator",
            ),
        ]

        detections = detect_username_enumeration(
            events,
            threshold=3,
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Possible Username Enumeration",
        )

    # ---------------------------------------------------------
    # NETWORK
    # ---------------------------------------------------------

    def test_port_scanning(self):

        events = [
            self.make_event(
                event_type="network_connection",
                destination_port=port,
                source="firewall",
                message=f"Connection attempt to port {port}",
            )
            for port in [21, 22, 23, 80, 443]
        ]

        detections = detect_port_scanning(
            events,
            threshold=5,
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Possible Port Scanning",
        )

    def test_firewall_block_detection(self):

        events = [
            self.make_event(
                event_type="firewall_block",
                source="firewall",
                message="Firewall blocked connection from 192.168.1.100",
            )
            for _ in range(5)
        ]

        detections = detect_firewall_blocks(
            events,
            threshold=5,
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Firewall Block Spike",
        )

    # ---------------------------------------------------------
    # WEB SCANNING
    # ---------------------------------------------------------

    def test_web_directory_scanning(self):

        paths = [
            "/admin",
            "/login",
            "/backup",
            "/config",
        ]

        events = [
            self.make_event(
                event_type="http_request",
                source="apache",
                message=f'GET {path} HTTP/1.1',
                metadata={
                    "path": path,
                    "method": "GET",
                },
            )
            for path in paths
        ]

        detections = detect_web_scanning(
            events,
            threshold=4,
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Web Directory Scanning",
        )

    # ---------------------------------------------------------
    # INJECTION ATTACKS
    # ---------------------------------------------------------

    def test_sql_injection_detection(self):

        event = self.make_event(
            event_type="http_request",
            source="apache",
            message="GET /login?id=1%27%20OR%201%3D1 HTTP/1.1",
            metadata={
                "path": "/login?id=1%27%20OR%201%3D1",
            },
        )

        detections = detect_sql_injection(
            [event]
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Possible SQL Injection",
        )

    def test_xss_detection(self):

        event = self.make_event(
            event_type="http_request",
            source="apache",
            message="GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1",
            metadata={
                "path": "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            },
        )

        detections = detect_xss(
            [event]
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Possible XSS",
        )

    def test_path_traversal_detection(self):

        event = self.make_event(
            event_type="http_request",
            source="nginx",
            message="GET /../../etc/passwd HTTP/1.1",
            metadata={
                "path": "/../../etc/passwd",
            },
        )

        detections = detect_path_traversal(
            [event]
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Path Traversal Attempt",
        )

    def test_command_injection_detection(self):

        event = self.make_event(
            event_type="http_request",
            source="apache",
            message="GET /ping?host=127.0.0.1;id HTTP/1.1",
            metadata={
                "path": "/ping?host=127.0.0.1;id",
            },
        )

        detections = detect_command_injection(
            [event]
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Possible Command Injection",
        )

    # ---------------------------------------------------------
    # SENSITIVE RESOURCES
    # ---------------------------------------------------------

    def test_sensitive_path_detection(self):

        event = self.make_event(
            event_type="http_request",
            source="nginx",
            message="GET /.env HTTP/1.1",
            metadata={
                "path": "/.env",
            },
        )

        detections = detect_sensitive_paths(
            [event]
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Sensitive Resource Access",
        )

    # ---------------------------------------------------------
    # USER AGENT
    # ---------------------------------------------------------

    def test_suspicious_user_agent(self):

        event = self.make_event(
            event_type="http_request",
            source="apache",
            message="GET / HTTP/1.1",
            metadata={
                "user_agent": "sqlmap/1.7.2",
            },
        )

        detections = detect_suspicious_user_agents(
            [event]
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "Suspicious User Agent",
        )

    # ---------------------------------------------------------
    # HTTP ERRORS
    # ---------------------------------------------------------

    def test_http_error_spike(self):

        events = [
            self.make_event(
                event_type="http_response",
                source="nginx",
                message="GET / HTTP/1.1 404",
                metadata={
                    "status_code": 404,
                },
            )
            for _ in range(5)
        ]

        detections = detect_http_error_spike(
            events,
            threshold=5,
        )

        self.assertTrue(
            len(detections) >= 1
        )

        self.assertEqual(
            detections[0]["type"],
            "HTTP Error Spike",
        )

    # ---------------------------------------------------------
    # FULL DETECTION ENGINE
    # ---------------------------------------------------------

    def test_run_detections_returns_list(self):

        events = [
            self.make_event(
                username="root",
            )
            for _ in range(5)
        ]

        detections = run_detections(
            events
        )

        self.assertIsInstance(
            detections,
            list,
        )

        self.assertTrue(
            len(detections) > 0
        )

    # ---------------------------------------------------------
    # INCIDENT ENGINE
    # ---------------------------------------------------------

    def test_incident_creation(self):

        detections = [

            {
                "type":
                    "Repeated Authentication Failures",

                "severity":
                    "HIGH",

                "source_ip":
                    "192.168.1.100",

                "description":
                    "Multiple failed authentication attempts.",

                "count":
                    10,
            },

            {
                "type":
                    "Privileged Account Targeting",

                "severity":
                    "HIGH",

                "source_ip":
                    "192.168.1.100",

                "description":
                    "Privileged account targeted.",

                "username":
                    "root",
            },

        ]

        engine = IncidentEngine()

        incidents = (
            engine.create_incidents(
                detections
            )
        )

        self.assertEqual(
            len(incidents),
            1,
        )

        incident = incidents[0]

        self.assertEqual(
            incident["source_ip"],
            "192.168.1.100",
        )

        self.assertEqual(
            incident["status"],
            "OPEN",
        )

        self.assertGreater(
            incident["risk_score"],
            0,
        )

        self.assertEqual(
            incident["detection_count"],
            2,
        )

        self.assertEqual(
            len(incident["attack_types"]),
            2,
        )

    def test_incident_risk_score_capped(self):

        detections = []

        attack_types = [
            "Repeated Authentication Failures",
            "Privileged Account Targeting",
            "Possible Username Enumeration",
            "Possible Port Scanning",
            "Web Directory Scanning",
            "Path Traversal Attempt",
            "Sensitive Resource Access",
            "HTTP Error Spike",
        ]

        for attack_type in attack_types:

            detections.append({

                "type":
                    attack_type,

                "severity":
                    "CRITICAL",

                "source_ip":
                    "10.0.0.50",

            })

        engine = IncidentEngine()

        incidents = (
            engine.create_incidents(
                detections
            )
        )

        self.assertEqual(
            len(incidents),
            1,
        )

        self.assertLessEqual(
            incidents[0]["risk_score"],
            100,
        )

    def test_correlation_detection_does_not_count_as_attack_behavior(self):

        detections = [

            {
                "type":
                    "Repeated Authentication Failures",

                "severity":
                    "HIGH",

                "source_ip":
                    "192.168.1.100",
            },

            {
                "type":
                    "Correlated Suspicious Activity",

                "severity":
                    "HIGH",

                "source_ip":
                    "192.168.1.100",
            },

        ]

        engine = IncidentEngine()

        incidents = (
            engine.create_incidents(
                detections
            )
        )

        self.assertEqual(
            len(incidents),
            1,
        )

        incident = incidents[0]

        self.assertEqual(
            incident["detection_count"],
            1,
        )

        self.assertEqual(
            len(incident["attack_types"]),
            1,
        )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )
