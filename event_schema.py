from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class SecurityEvent:
    """
    Universal normalized security event.

    Every parser should convert its log entries
    into this common structure.
    """

    timestamp: Optional[str] = None
    source: str = "unknown"
    event_type: str = "unknown"

    severity: str = "INFO"

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None

    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    username: Optional[str] = None
    hostname: Optional[str] = None

    message: str = ""
    raw_log: str = ""

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        """Convert the event into a dictionary."""
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "username": self.username,
            "hostname": self.hostname,
            "message": self.message,
            "raw_log": self.raw_log,
            "metadata": self.metadata,
        }
