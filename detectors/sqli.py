from collections import defaultdict
from core.finding import Finding

SQLI_PATTERNS = [
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "union select",
    "--",
    ";--",
    "'--",
    "\"--",
    " or 1=1",
    "sleep(",
    "benchmark("
]

THRESHOLD = 3


def detect_sqli(parsed_logs: list):
    """
    Detects possible SQL Injection attempts from access logs.
    """
    findings = []
    tracker = defaultdict(list)

    for entry in parsed_logs:
        ip = entry["ip"]
        payload_source = (
            entry["path"] + " " + entry["query"]
        ).lower()

        for pattern in SQLI_PATTERNS:
            if pattern in payload_source:
                tracker[ip].append((pattern, entry))
                break  # WHY: avoid double counting same request

    for ip, matches in tracker.items():
        if len(matches) >= THRESHOLD:
            endpoints = {m[1]["path"] for m in matches}
            evidence = list({m[0] for m in matches})

            findings.append(
                Finding(
                    title="Possible SQL Injection Attempts",
                    category="SQL Injection",
                    severity="High",
                    description=(
                        "Multiple SQL injection payloads detected "
                        "from the same IP address"
                    ),
                    ip=ip,
                    endpoint=", ".join(endpoints),
                    evidence=evidence,
                    count=len(matches)
                )
            )

    return findings
