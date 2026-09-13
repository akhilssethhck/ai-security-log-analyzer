import re
from event_schema import SecurityEvent


class FirewallParser:
    """Parser for common firewall/network log formats."""

    name = "FIREWALL"

    def can_parse(self, lines):
        indicators = [
            "SRC=",
            "DST=",
            "SPT=",
            "DPT=",
            "ACTION=",
            "BLOCK",
            "DENY",
            "ALLOW",
        ]

        sample = "\n".join(lines[:50]).upper()

        score = sum(
            indicator in sample
            for indicator in indicators
        )

        return score >= 2

    def parse(self, lines):
        events = []

        for line in lines:
            raw = line.strip()

            if not raw:
                continue

            upper = raw.upper()

            source_ip = self._extract(r"SRC=(\S+)", raw)
            destination_ip = self._extract(r"DST=(\S+)", raw)

            source_port = self._extract_int(
                r"SPT=(\d+)", raw
            )

            destination_port = self._extract_int(
                r"DPT=(\d+)", raw
            )

            protocol = self._extract(
                r"PROTO=(\S+)", raw
            )

            action = self._detect_action(upper)

            if action in {"BLOCK", "DENY", "DROP", "REJECT"}:
                event_type = "firewall_block"
                severity = "MEDIUM"

            elif action == "ALLOW":
                event_type = "firewall_allow"
                severity = "INFO"

            else:
                event_type = "network_activity"
                severity = "INFO"

            events.append(
                SecurityEvent(
                    source="firewall",
                    event_type=event_type,
                    severity=severity,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    source_port=source_port,
                    destination_port=destination_port,
                    message=raw,
                    raw_log=raw,
                    metadata={
                        "protocol": protocol,
                        "action": action,
                    },
                )
            )

        return events

    @staticmethod
    def _extract(pattern, text):
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1) if match else None

    @staticmethod
    def _extract_int(pattern, text):
        value = FirewallParser._extract(pattern, text)

        try:
            return int(value) if value else None
        except ValueError:
            return None

    @staticmethod
    def _detect_action(text):
        for action in [
            "BLOCK",
            "DENY",
            "DROP",
            "REJECT",
            "ALLOW",
        ]:
            if action in text:
                return action

        return "UNKNOWN"
