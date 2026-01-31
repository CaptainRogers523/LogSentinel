import os
from datetime import datetime

def generate_markdown_report(findings, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(
        output_dir, "logsentinel_report.md"
    )

    lines = []
    lines.append("# 🛡️ LogSentinel Security Report\n")
    lines.append(f"Generated at: {datetime.utcnow().isoformat()}\n")
    lines.append(f"Total Findings: {len(findings)}\n")
    lines.append("---\n")

    if not findings:
        lines.append("✅ No suspicious activity detected.\n")
    else:
        for i, f in enumerate(findings, 1):
            lines.append(f"## {i}. {f.title}")
            lines.append(f"- Severity: {f.severity}")
            lines.append(f"- IP: {f.ip}")
            lines.append(f"- Endpoint: {f.endpoint}")
            lines.append(f"- Attempts: {f.count}")
            lines.append("\nEvidence:")
            for e in f.evidence:
                lines.append(f"- `{e}`")
            lines.append("\n---\n")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return output_file
