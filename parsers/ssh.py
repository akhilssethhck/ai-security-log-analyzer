import re
from event_schema import SecurityEvent


class SSHParser:
    """Parser for Linux SSH authentication logs."""

    name = "SSH_AUTH"

    def can_parse(self, lines):
        """Check whether the log looks like an SSH authentication log."""

        sample = "\n".join(lines[:50])

        ssh_indicators = [
            "sshd",
            "Accepted password",
            "Failed password",
            "authentication failure",
        ]

        return any(
            indicator in sample
            for indicator in ssh_indicators
        )

    def parse(self, lines):
        """Convert SSH log lines into normalized SecurityEvent objects."""

        events = []

        for line in lines:
            line = line.strip()

            if not line:
                continue

            # ----------------------------------------------------
            # Extract source IP
            # ----------------------------------------------------

            ip_match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)",
                line
            )

            source_ip = (
                ip_match.group(1)
                if ip_match
                else None
            )

            # ----------------------------------------------------
            # Extract username
            # ----------------------------------------------------

            username_match = re.search(
                r"(?:for|invalid user)\s+(\S+)",
                line,
                re.IGNORECASE
            )

            username = (
                username_match.group(1)
                if username_match
                else None
            )

            # ----------------------------------------------------
            # Determine event type and severity
            # ----------------------------------------------------

            if "Accepted password" in line:

                event_type = "authentication_success"
                severity = "LOW"

            elif "Failed password" in line:

                event_type = "authentication_failure"

                if username and username.lower() in {
                    "root",
                    "admin",
                    "administrator",
                    "superuser"
                }:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

            elif "authentication failure" in line.lower():

                event_type = "authentication_failure"
                severity = "MEDIUM"

            else:

                event_type = "ssh_activity"
                severity = "INFO"

            # ----------------------------------------------------
            # Extract SSH client/source port
            #
            # IMPORTANT:
            # In sshd authentication logs, the port shown after
            # the source IP is normally the CLIENT SOURCE PORT.
            # It is NOT the destination/service port.
            # ----------------------------------------------------

            port_match = re.search(
                r"\bport\s+(\d+)\b",
                line,
                re.IGNORECASE
            )

            source_port = (
                int(port_match.group(1))
                if port_match
                else None
            )

            # We intentionally leave destination_port as None.
            # The SSH log does not establish the destination port.
            destination_port = None

            # ----------------------------------------------------
            # Create normalized SecurityEvent
            # ----------------------------------------------------

            event = SecurityEvent(
                source="ssh",
                event_type=event_type,
                severity=severity,
                source_ip=source_ip,
                source_port=source_port,
                destination_port=destination_port,
                username=username,
                message=line,
                raw_log=line,
            )

            events.append(event)

        return events
