import re
from event_schema import SecurityEvent


class NginxParser:
    """Parser for Nginx HTTP access logs."""

    name = "NGINX_ACCESS"

    def can_parse(self, lines):
        """
        Detect a common Nginx combined access-log format.
        """

        pattern = re.compile(
            r'^\S+ - \S+ \[[^\]]+\] '
            r'"\S+ [^"]+ HTTP/\d\.\d" \d{3}'
        )

        return any(
            pattern.search(line.strip())
            for line in lines[:50]
        )

    def parse(self, lines):
        """Convert Nginx access logs into SecurityEvent objects."""

        events = []

        pattern = re.compile(
            r'^(\S+) - \S+ '
            r'\[([^\]]+)\] '
            r'"(\S+) ([^"]+) HTTP/[\d.]+" '
            r'(\d{3})'
            r'(?: (\d+))?'
        )

        suspicious_patterns = [
            "../",
            "..\\",
            "union select",
            "select%20",
            "<script",
            "%3cscript",
            "etc/passwd",
            "etc%2fpasswd",
            ".env",
            "wp-admin",
            "phpmyadmin",
            "cmd.exe",
            "/bin/sh",
            "/bin/bash",
        ]

        for line in lines:
            line = line.strip()

            if not line:
                continue

            match = pattern.search(line)

            if not match:
                continue

            source_ip = match.group(1)
            timestamp = match.group(2)
            method = match.group(3)
            path = match.group(4)
            status_code = int(match.group(5))

            lowered_path = path.lower()

            if any(
                item in lowered_path
                for item in suspicious_patterns
            ):
                event_type = "suspicious_web_request"
                severity = "HIGH"

            elif status_code >= 500:
                event_type = "server_error"
                severity = "MEDIUM"

            elif status_code >= 400:
                event_type = "http_error"
                severity = "LOW"

            else:
                event_type = "http_request"
                severity = "INFO"

            events.append(
                SecurityEvent(
                    timestamp=timestamp,
                    source="nginx",
                    event_type=event_type,
                    severity=severity,
                    source_ip=source_ip,
                    message=line,
                    raw_log=line,
                    metadata={
                        "method": method,
                        "path": path,
                        "status_code": status_code,
                    },
                )
            )

        return events
