import re
from event_schema import SecurityEvent


class ApacheParser:
    """Parser for Apache HTTP access logs."""

    name = "APACHE_ACCESS"

    def can_parse(self, lines):
        """Detect common Apache access-log format."""

        pattern = re.compile(
            r'^\S+ \S+ \S+ \[[^\]]+\] '
            r'"\S+ [^"]+ HTTP/\d\.\d" \d{3}'
        )

        return any(pattern.search(line.strip()) for line in lines[:50])

    def parse(self, lines):
        """Convert Apache access logs into normalized events."""

        events = []

        pattern = re.compile(
            r'^(\S+) \S+ \S+ '
            r'\[([^\]]+)\] '
            r'"(\S+) ([^"]+) HTTP/[\d.]+" '
            r'(\d{3})'
            r'(?: (\d+))?'
        )

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

            # Basic web-security classification
            suspicious_patterns = [
                "../",
                "..\\",
                "union select",
                "<script",
                "etc/passwd",
                "wp-admin",
                ".env",
            ]

            lowered_path = path.lower()

            if any(
                pattern in lowered_path
                for pattern in suspicious_patterns
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

            event = SecurityEvent(
                timestamp=timestamp,
                source="apache",
                event_type=event_type,
                severity=severity,
                source_ip=source_ip,
                username=None,
                message=line,
                raw_log=line,
                metadata={
                    "method": method,
                    "path": path,
                    "status_code": status_code,
                },
            )

            events.append(event)

        return events
