from collections import defaultdict
from core.finding import Finding

SENSITIVE_PATHS = [
    "/login",
    "/admin",
    "/signin",
    "/wp-login"
]

THRESHOLD = 10  # WHY: below this can be human behavior


def detect_brute_force(parsed_logs: list):
    """
    Detects brute force attempts based on repeated access to auth endpoints.
    Returns list of Finding objects.
    """
    findings = []
    tracker = defaultdict(list)

    # Step 1: Track attempts
    for entry in parsed_logs:
        path = entry["path"].lower()
        ip = entry["ip"]

        if any(sensitive in path for sensitive in SENSITIVE_PATHS):
            key = (ip, path)
            tracker[key].append(entry)

    # Step 2: Analyze patterns
    for (ip, path), attempts in tracker.items():
        if len(attempts) >= THRESHOLD:
            findings.append(
                Finding(
                    title="Possible Brute Force Attack",
                    category="Brute Force",
                    severity="High",
                    description=(
                        f"Multiple authentication attempts detected "
                        f"from the same IP to {path}"
                    ),
                    ip=ip,
                    endpoint=path,
                    evidence=[
                        a["raw"] for a in attempts[:3]
                    ],
                    count=len(attempts)
                )
            )

    return findings
