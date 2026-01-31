from collections import defaultdict
from urllib.parse import unquote
from core.finding import Finding

TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
    "%2e%2e",
    "%2f",
    "%5c",
    "/etc/passwd",
    "windows/system32"
]

THRESHOLD = 2


def detect_path_traversal(parsed_logs: list):
    """
    Detects possible path traversal attempts from access logs.
    """
    findings = []
    tracker = defaultdict(list)

    for entry in parsed_logs:
        ip = entry["ip"]

        payload_source = unquote(
            entry["path"] + " " + entry["query"]
        ).lower()

        for pattern in TRAVERSAL_PATTERNS:
            if pattern in payload_source:
                tracker[ip].append((pattern, entry))
                break  # avoid duplicate count

    for ip, matches in tracker.items():
        if len(matches) >= THRESHOLD:
            endpoints = {m[1]["path"] for m in matches}
            evidence = list({m[0] for m in matches})

            findings.append(
                Finding(
                    title="Possible Path Traversal Attempts",
                    category="Path Traversal",
                    severity="High",
                    description=(
                        "Requests attempting directory traversal "
                        "or access to sensitive system files"
                    ),
                    ip=ip,
                    endpoint=", ".join(endpoints),
                    evidence=evidence,
                    count=len(matches)
                )
            )

    return findings
