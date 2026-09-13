import csv
import json
import os

from event_schema import SecurityEvent
from parsers.ssh import SSHParser
from parsers.apache import ApacheParser
from parsers.nginx import NginxParser
from parsers.firewall import FirewallParser


class ParserManager:

    """
    Universal Parser Manager

    Supports:
    - SSH
    - Apache
    - Nginx
    - Firewall
    - Mixed log files
    - JSON
    - CSV
    - TXT
    """

    def __init__(self):

        self.parsers = [
            SSHParser(),
            ApacheParser(),
            NginxParser(),
            FirewallParser(),
        ]


    def detect_line_parser(self, line):

        """
        Detect which parser recognizes ONE line.
        """

        for parser in self.parsers:

            try:

                if parser.can_parse([line]):
                    return parser

            except Exception:
                continue

        return None


    def _parse_text_file(self, file_path):

        """
        Parse plain-text/log files line-by-line.
        """

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            lines = file.readlines()

        if not lines:
            raise ValueError("The log file is empty.")

        events = []
        detected_types = set()

        for line in lines:

            line = line.strip()

            if not line:
                continue

            parser = self.detect_line_parser(line)

            if parser is None:
                continue

            try:

                parsed_events = parser.parse([line])

                if parsed_events:

                    events.extend(parsed_events)
                    detected_types.add(parser.name)

            except Exception:
                continue

        if not events:

            raise ValueError(
                "No supported parser recognized this log format."
            )

        if len(detected_types) == 1:
            detected_name = next(iter(detected_types))
        else:
            detected_name = "MIXED"

        return detected_name, events


    def _normalize_structured_event(self, record, raw_record):

        """
        Convert a JSON/CSV record into SecurityEvent.

        Supports common security-log field names while
        preserving unknown fields inside metadata.
        """

        if not isinstance(record, dict):
            return None

        def get_value(*keys, default=None):

            for key in keys:

                if key in record:

                    value = record.get(key)

                    if value not in (None, ""):
                        return value

            return default


        timestamp = get_value(
            "timestamp",
            "time",
            "datetime",
            "date",
            default=""
        )

        source = get_value(
            "source",
            "service",
            "application",
            "app",
            "program",
            default="structured"
        )

        event_type = get_value(
            "event_type",
            "event",
            "type",
            "action",
            "eventType",
            default="security_event"
        )

        severity = get_value(
            "severity",
            "level",
            "priority",
            default="INFO"
        )

        source_ip = get_value(
            "source_ip",
            "src_ip",
            "src",
            "sourceIP",
            "client_ip",
            "clientIP",
            "ip"
        )

        destination_ip = get_value(
            "destination_ip",
            "dst_ip",
            "dst",
            "destinationIP",
            "server_ip",
            "serverIP"
        )

        source_port = get_value(
            "source_port",
            "src_port",
            "sourcePort"
        )

        destination_port = get_value(
            "destination_port",
            "dst_port",
            "destinationPort",
            "port"
        )

        username = get_value(
            "username",
            "user",
            "account",
            "user_name"
        )

        hostname = get_value(
            "hostname",
            "host",
            "computer",
            "machine"
        )

        message = get_value(
            "message",
            "msg",
            "description",
            "log",
            "event_message",
            default=""
        )

        known_fields = {
            "timestamp",
            "time",
            "datetime",
            "date",
            "source",
            "service",
            "application",
            "app",
            "program",
            "event_type",
            "event",
            "type",
            "action",
            "eventType",
            "severity",
            "level",
            "priority",
            "source_ip",
            "src_ip",
            "src",
            "sourceIP",
            "client_ip",
            "clientIP",
            "ip",
            "destination_ip",
            "dst_ip",
            "dst",
            "destinationIP",
            "server_ip",
            "serverIP",
            "source_port",
            "src_port",
            "sourcePort",
            "destination_port",
            "dst_port",
            "destinationPort",
            "port",
            "username",
            "user",
            "account",
            "user_name",
            "hostname",
            "host",
            "computer",
            "machine",
            "message",
            "msg",
            "description",
            "log",
            "event_message",
        }

        metadata = {
            key: value
            for key, value in record.items()
            if key not in known_fields
        }

        return SecurityEvent(
            timestamp=str(timestamp),
            source=str(source),
            event_type=str(event_type),
            severity=str(severity).upper(),
            source_ip=str(source_ip) if source_ip else None,
            destination_ip=(
                str(destination_ip)
                if destination_ip
                else None
            ),
            source_port=self._safe_int(source_port),
            destination_port=self._safe_int(destination_port),
            username=str(username) if username else None,
            hostname=str(hostname) if hostname else None,
            message=str(message),
            raw_log=str(raw_record),
            metadata=metadata,
        )


    @staticmethod
    def _safe_int(value):

        if value in (None, ""):
            return None

        try:
            return int(value)

        except (TypeError, ValueError):
            return None


    def _parse_json_file(self, file_path):

        """
        Parse JSON security logs.

        Supports:
        - JSON object
        - JSON array
        - {"events": [...]}
        - {"logs": [...]}
        - {"records": [...]}
        """

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            data = json.load(file)

        records = []

        if isinstance(data, list):

            records = data

        elif isinstance(data, dict):

            for key in (
                "events",
                "logs",
                "records",
                "results",
                "data",
            ):

                if isinstance(data.get(key), list):

                    records = data[key]
                    break

            if not records:
                records = [data]

        else:

            raise ValueError(
                "Unsupported JSON structure."
            )

        events = []

        for record in records:

            event = self._normalize_structured_event(
                record,
                record
            )

            if event:
                events.append(event)

        if not events:

            raise ValueError(
                "No usable security events found in JSON file."
            )

        return "JSON", events


    def _parse_csv_file(self, file_path):

        """
        Parse CSV security logs using column names.
        """

        with open(
            file_path,
            "r",
            encoding="utf-8-sig",
            errors="replace",
            newline=""
        ) as file:

            reader = csv.DictReader(file)

            if not reader.fieldnames:

                raise ValueError(
                    "CSV file does not contain a header row."
                )

            events = []

            for row in reader:

                event = self._normalize_structured_event(
                    row,
                    row
                )

                if event:
                    events.append(event)

        if not events:

            raise ValueError(
                "No usable security events found in CSV file."
            )

        return "CSV", events


    def parse_file(self, file_path):

        """
        Automatically select the parser based on file extension.
        """

        if not os.path.isfile(file_path):

            raise FileNotFoundError(
                f"Log file does not exist: {file_path}"
            )

        extension = os.path.splitext(
            file_path
        )[1].lower()

        if extension == ".json":

            return self._parse_json_file(file_path)

        if extension == ".csv":

            return self._parse_csv_file(file_path)

        if extension in {".log", ".txt"}:

            return self._parse_text_file(file_path)

        raise ValueError(
            "Unsupported file type. "
            "Use .log, .txt, .json or .csv."
        )


    def list_parsers(self):

        return [
            parser.name
            for parser in self.parsers
        ]
