import re


def detect_log_type(file_path):
    """
    Identify the likely log format from sample lines.
    """

    try:
        with open(file_path, "r", errors="ignore") as file:
            lines = [line.strip() for line in file if line.strip()][:100]

    except FileNotFoundError:
        return "UNKNOWN"

    if not lines:
        return "EMPTY"

    content = "\n".join(lines)

    # Linux SSH / authentication logs
    ssh_patterns = [
        r"Failed password",
        r"Accepted password",
        r"sshd",
        r"authentication failure",
    ]

    if sum(bool(re.search(pattern, content, re.IGNORECASE))
           for pattern in ssh_patterns) >= 2:
        return "SSH_AUTH"

    # Apache access logs
    if any(
        re.search(
            r'"\s*(GET|POST|PUT|DELETE|HEAD|PATCH)\s+',
            line,
            re.IGNORECASE
        )
        for line in lines
    ):
        return "WEB_ACCESS"

    # Firewall-style logs
    firewall_patterns = [
        r"\bACCEPT\b",
        r"\bDROP\b",
        r"\bDENY\b",
        r"\bBLOCK\b",
        r"\bREJECT\b",
    ]

    if any(
        re.search(pattern, content, re.IGNORECASE)
        for pattern in firewall_patterns
    ):
        return "FIREWALL"

    return "UNKNOWN"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 log_detector.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    log_type = detect_log_type(log_file)

    print(f"Detected log type: {log_type}")
