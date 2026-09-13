from collections import defaultdict
from urllib.parse import unquote
import re

# ============================================================
# UNIVERSAL EVENT HELPERS
# ============================================================

def get_field(event, field, default=None):
    if isinstance(event, dict):
        return event.get(field, default)
    return getattr(event, field, default)


def get_message(event):
    return str(get_field(event, "message", "") or "")


def get_source_ip(event):
    return get_field(event, "source_ip")


def get_username(event):
    return get_field(event, "username")


def get_event_type(event):
    return str(get_field(event, "event_type", "") or "").lower()


def get_source(event):
    return str(get_field(event, "source", "") or "").lower()


def get_destination_port(event):
    return get_field(event, "destination_port")


def get_status_code(event):
    value = get_field(event, "metadata", {})
    if isinstance(value, dict):
        return value.get("status_code")
    return get_field(event, "status_code")


# ============================================================
# 1. REPEATED AUTHENTICATION FAILURES
# ============================================================

def detect_repeated_auth_failures(events, threshold=5):
    activity = defaultdict(int)
    results = []

    for event in events:
        event_type = get_event_type(event)

        if "authentication_failure" not in event_type:
            continue

        ip = get_source_ip(event)

        if ip:
            activity[ip] += 1

    for ip, count in activity.items():
        if count >= threshold:
            results.append({
                "type": "Repeated Authentication Failures",
                "severity": "HIGH",
                "source_ip": ip,
                "count": count,
                "description":
                    f"{count} failed authentication attempts were observed "
                    f"from {ip}."
            })

    return results


# ============================================================
# 2. PRIVILEGED ACCOUNT TARGETING
# ============================================================

def detect_privileged_accounts(events):
    privileged = {
        "root",
        "admin",
        "administrator",
        "superuser"
    }

    activity = defaultdict(lambda: defaultdict(int))

    for event in events:
        event_type = get_event_type(event)

        if "authentication_failure" not in event_type:
            continue

        username = get_username(event)
        ip = get_source_ip(event)

        if not username or not ip:
            continue

        username = str(username).lower()

        if username in privileged:
            activity[ip][username] += 1

    results = []

    for ip, accounts in activity.items():

        total_attempts = sum(accounts.values())
        account_names = sorted(accounts.keys())

        results.append({
            "type": "Privileged Account Targeting",
            "severity": "HIGH",
            "source_ip": ip,
            "username": ", ".join(account_names),
            "count": total_attempts,
            "description":
                f"{total_attempts} authentication attempts targeted "
                f"privileged accounts: "
                f"{', '.join(account_names)}."
        })

    return results

# ============================================================
# 3. USERNAME ENUMERATION
# ============================================================

def detect_username_enumeration(events, threshold=3):
    users_by_ip = defaultdict(set)

    for event in events:
        if "authentication_failure" not in get_event_type(event):
            continue

        ip = get_source_ip(event)
        username = get_username(event)

        if ip and username:
            users_by_ip[ip].add(str(username))

    results = []

    for ip, usernames in users_by_ip.items():
        if len(usernames) >= threshold:
            results.append({
                "type": "Possible Username Enumeration",
                "severity": "MEDIUM",
                "source_ip": ip,
                "count": len(usernames),
                "description":
                    f"{len(usernames)} different usernames were targeted "
                    f"from {ip}."
            })

    return results


# ============================================================
# 4. PORT SCANNING
# ============================================================

def detect_port_scanning(events, threshold=5):
    ports_by_ip = defaultdict(set)

    for event in events:
        ip = get_source_ip(event)
        port = get_destination_port(event)

        if not ip or not port:
            continue

        try:
            port = int(port)
        except (ValueError, TypeError):
            continue

        ports_by_ip[ip].add(port)

    results = []

    for ip, ports in ports_by_ip.items():
        if len(ports) >= threshold:
            results.append({
                "type": "Possible Port Scanning",
                "severity": "HIGH",
                "source_ip": ip,
                "count": len(ports),
                "description":
                    f"{len(ports)} different destination ports were "
                    f"observed from {ip}."
            })

    return results


# ============================================================
# 5. FIREWALL BLOCK SPIKE
# ============================================================

def detect_firewall_blocks(events, threshold=5):
    blocked = defaultdict(int)

    for event in events:
        event_type = get_event_type(event)

        if "firewall_block" not in event_type:
            continue

        ip = get_source_ip(event)

        if ip:
            blocked[ip] += 1

    results = []

    for ip, count in blocked.items():
        if count >= threshold:
            results.append({
                "type": "Firewall Block Spike",
                "severity": "HIGH",
                "source_ip": ip,
                "count": count,
                "description":
                    f"{count} firewall blocks were observed from {ip}."
            })

    return results


# ============================================================
# 6. WEB PATH SCANNING
# ============================================================

def detect_web_scanning(events, threshold=4):
    paths_by_ip = defaultdict(set)

    for event in events:
        event_type = get_event_type(event)

        if not any(x in event_type for x in [
            "http_request",
            "http_error",
            "suspicious_web_request"
        ]):
            continue

        ip = get_source_ip(event)

        message = get_message(event)

        match = re.search(
            r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)',
            message,
            re.IGNORECASE
        )

        if not match:
            match = re.search(
                r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)',
                message,
                re.IGNORECASE
            )

        if ip and match:
            paths_by_ip[ip].add(match.group(1))

    results = []

    for ip, paths in paths_by_ip.items():
        if len(paths) >= threshold:
            results.append({
                "type": "Web Directory Scanning",
                "severity": "MEDIUM",
                "source_ip": ip,
                "count": len(paths),
                "description":
                    f"{len(paths)} different web paths were requested "
                    f"from {ip}, indicating possible web reconnaissance."
            })

    return results


# ============================================================
# 7. SQL INJECTION
# ============================================================

def detect_sql_injection(events):
    patterns = [
        r"\bunion\b.*\bselect\b",
        r"\bor\b\s+\d+\s*=\s*\d+",
        r"\band\b\s+\d+\s*=\s*\d+",
        r"'\s*or\s*'",
        r"\bsleep\s*\(",
        r"\bbenchmark\s*\(",
        r"\bselect\b.*\bfrom\b",
        r"\bdrop\s+table\b",
        r"\binformation_schema\b",
    ]

    results = []

    for event in events:
        message = get_message(event)

        # Decode URL-encoded web requests.
        # Example:
        # %20OR%201=1
        # becomes:
        #  OR 1=1
        decoded_message = unquote(message)

        for pattern in patterns:
            if re.search(
                pattern,
                decoded_message,
                re.IGNORECASE
            ):
                results.append({
                    "type": "SQL Injection Attempt",
                    "severity": "CRITICAL",
                    "source_ip": get_source_ip(event),
                    "count": 1,
                    "description":
                        "A web request contains a pattern commonly "
                        "associated with SQL injection."
                })
                break

    return results

# ============================================================
# 8. CROSS-SITE SCRIPTING
# ============================================================

def detect_xss(events):
    patterns = [
        r"<script\b",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<iframe\b",
        r"alert\s*\("
    ]

    results = []

    for event in events:
        message = get_message(event)

        for pattern in patterns:
            if re.search(pattern, message, re.IGNORECASE):
                results.append({
                    "type": "Cross-Site Scripting Attempt",
                    "severity": "HIGH",
                    "source_ip": get_source_ip(event),
                    "count": 1,
                    "description":
                        "A web request contains a pattern commonly "
                        "associated with XSS."
                })
                break

    return results


# ============================================================
# 9. PATH TRAVERSAL
# ============================================================

def detect_path_traversal(events):
    patterns = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e",
        r"%252e%252e",
        r"/etc/passwd",
        r"/etc/shadow",
        r"boot\.ini",
        r"win\.ini"
    ]

    results = []

    for event in events:
        message = get_message(event)

        for pattern in patterns:
            if re.search(pattern, message, re.IGNORECASE):
                results.append({
                    "type": "Path Traversal Attempt",
                    "severity": "CRITICAL",
                    "source_ip": get_source_ip(event),
                    "count": 1,
                    "description":
                        "A request contains a pattern associated with "
                        "path traversal or sensitive file access."
                })
                break

    return results


# ============================================================
# 10. COMMAND INJECTION
# ============================================================

def detect_command_injection(events):
    patterns = [
        r";\s*(cat|ls|id|whoami|pwd|uname|wget|curl|bash|sh)\b",
        r"\|\s*(cat|ls|id|whoami|pwd|uname|wget|curl|bash|sh)\b",
        r"`[^`]+`",
        r"\$\([^)]*\)",
        r"\b(?:wget|curl)\s+https?://"
    ]

    results = []

    for event in events:
        message = get_message(event)

        for pattern in patterns:
            if re.search(pattern, message, re.IGNORECASE):
                results.append({
                    "type": "Command Injection Attempt",
                    "severity": "CRITICAL",
                    "source_ip": get_source_ip(event),
                    "count": 1,
                    "description":
                        "A web request contains a pattern associated "
                        "with operating-system command injection."
                })
                break

    return results


# ============================================================
# 11. SENSITIVE WEB PATH ACCESS
# ============================================================

def detect_sensitive_paths(events):
    sensitive_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/.env",
        "/.git",
        "/config",
        "/wp-admin",
        "/phpmyadmin",
        "/admin",
        "/administrator",
        "/server-status",
        "/backup",
        "/database"
    ]

    results = []

    for event in events:
        message = get_message(event)

        for path in sensitive_paths:
            if path.lower() in message.lower():
                results.append({
                    "type": "Sensitive Resource Access",
                    "severity": "HIGH",
                    "source_ip": get_source_ip(event),
                    "count": 1,
                    "description":
                        f"Request for sensitive resource '{path}' "
                        f"was observed."
                })
                break

    return results


# ============================================================
# 12. SUSPICIOUS USER AGENTS
# ============================================================

def detect_suspicious_user_agents(events):
    tools = [
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "gobuster",
        "dirbuster",
        "wpscan",
        "burpsuite",
        "python-requests",
        "curl",
        "wget"
    ]

    results = []

    for event in events:
        message = get_message(event)

        for tool in tools:
            if tool.lower() in message.lower():
                results.append({
                    "type": "Suspicious User Agent",
                    "severity": "MEDIUM",
                    "source_ip": get_source_ip(event),
                    "count": 1,
                    "description":
                        f"Possible automated security/scanning tool "
                        f"detected: {tool}."
                })
                break

    return results


# ============================================================
# 13. HTTP ERROR SPIKE
# ============================================================

def detect_http_error_spike(events, threshold=5):
    errors = defaultdict(int)

    for event in events:
        event_type = get_event_type(event)

        if event_type not in {
            "http_error",
            "http_request",
            "suspicious_web_request"
        }:
            continue

        status = get_status_code(event)

        try:
            status = int(status)
        except (ValueError, TypeError):
            continue

        if status >= 400:
            ip = get_source_ip(event)

            if ip:
                errors[ip] += 1

    results = []

    for ip, count in errors.items():
        if count >= threshold:
            results.append({
                "type": "HTTP Error Spike",
                "severity": "MEDIUM",
                "source_ip": ip,
                "count": count,
                "description":
                    f"{count} HTTP error responses were observed "
                    f"from {ip}."
            })

    return results


# ============================================================
# 14. CORRELATION ENGINE
# ============================================================

def correlate_detections(detections):
    activity = defaultdict(list)

    for detection in detections:
        ip = detection.get("source_ip")

        if ip:
            activity[ip].append(
                detection.get("type", "Unknown")
            )

    results = []

    for ip, types in activity.items():

        unique_types = list(dict.fromkeys(types))

        if len(unique_types) >= 2:
            results.append({
                "type": "Correlated Suspicious Activity",
                "severity": "CRITICAL",
                "source_ip": ip,
                "count": len(unique_types),
                "description":
                    f"Multiple suspicious behaviors were observed "
                    f"from {ip}: {', '.join(unique_types)}."
            })

    return results


# ============================================================
# MASTER DETECTION ENGINE
# ============================================================

def run_detections(events):

    detections = []

    detectors = [
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
    ]

    for detector in detectors:
        try:
            detections.extend(detector(events))
        except Exception as error:
            print(
                f"[WARNING] Detection module "
                f"{detector.__name__} failed: {error}"
            )

    detections.extend(
        correlate_detections(detections)
    )

    return detections
