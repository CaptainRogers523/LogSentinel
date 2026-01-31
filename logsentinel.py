import os
import argparse

from core.parser import parse_log_line
from core.scorer import calculate_severity
from core.deduplicator import deduplicate_findings

from detectors.brute_force import detect_brute_force
from detectors.sqli import detect_sqli
from detectors.xss import detect_xss
from detectors.traversal import detect_path_traversal

from reports.json_report import generate_json_report
from reports.markdown_report import generate_markdown_report


SEVERITY_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}


def filter_by_severity(findings, min_severity):
    threshold = SEVERITY_RANK[min_severity]
    return [
        f for f in findings
        if SEVERITY_RANK.get(f.severity, 0) >= threshold
    ]


def parse_args():
    parser = argparse.ArgumentParser(
        description="LogSentinel - Security-focused log analysis tool"
    )

    parser.add_argument(
        "--log",
        required=True,
        help="Path to access log file"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Generate JSON report"
    )

    parser.add_argument(
        "--md",
        action="store_true",
        help="Generate Markdown report"
    )

    parser.add_argument(
        "--min-severity",
        choices=["Low", "Medium", "High", "Critical"],
        default="Low",
        help="Minimum severity to include in report"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    log_path = os.path.abspath(args.log)
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")

    parsed_logs = []

    # 1️⃣ Parse logs
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                parsed_logs.append(parsed)

    # 2️⃣ Run detectors
    brute_force_findings = detect_brute_force(parsed_logs)
    sqli_findings = detect_sqli(parsed_logs)
    xss_findings = detect_xss(parsed_logs)
    traversal_findings = detect_path_traversal(parsed_logs)

    # 3️⃣ Collect findings
    all_findings = (
        brute_force_findings +
        sqli_findings +
        xss_findings +
        traversal_findings
    )

    # 4️⃣ Deduplicate
    final_findings = deduplicate_findings(all_findings)

    # 5️⃣ Severity scoring
    for f in final_findings:
        f.severity = calculate_severity(f)

    # 6️⃣ Severity filter
    final_findings = filter_by_severity(
        final_findings,
        args.min_severity
    )

    # 7️⃣ Report directory (FIXED LOCATION)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(base_dir, "reports")

    # 8️⃣ Generate reports
    if args.json:
        generate_json_report(final_findings, report_dir)

    if args.md:
        generate_markdown_report(final_findings, report_dir)

    print(f"[+] LogSentinel completed. Findings: {len(final_findings)}")


if __name__ == "__main__":
    main()
