from collections import defaultdict
from urllib.parse import unquote
from core.finding import Finding

XSS_PATTERNS = [
    "<script",
    "</script",
    "javascript:",
    "onerror=",
    "onload=",
    "alert(",
    "prompt(",
    "confirm("
]

THRESHOLD = 2


def detect_xss(parsed_logs: list):
    """
    Detects possible reflected XSS attempts from access logs.
    """
    findings = []
    tracker = defaultdict(list)

    for entry in parsed_logs:
        ip = entry["ip"]

        # Decode URL-encoded payloads
        payload_source = unquote(
            entry["path"] + " " + entry["query"]
        ).lower()

        for pattern in XSS_PATTERNS:
            if pattern in payload_source:
                tracker[ip].append((pattern, entry))
                break  # avoid double counting same request

    for ip, matches in tracker.items():
        if len(matches) >= THRESHOLD:
            endpoints = {m[1]["path"] for m in matches}
            evidence = list({m[0] for m in matches})

            findings.append(
                Finding(
                    title="Possible Cross-Site Scripting Attempts",
                    category="XSS",
                    severity="Medium",
                    description=(
                        "Suspicious XSS payloads detected in "
                        "request parameters or paths"
                    ),
                    ip=ip,
                    endpoint=", ".join(endpoints),
                    evidence=evidence,
                    count=len(matches)
                )
            )

    return findings
