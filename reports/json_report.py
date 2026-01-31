import json
import os
from datetime import datetime

def generate_json_report(findings, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(
        output_dir, "logsentinel_report.json"
    )

    report = {
        "tool": "LogSentinel",
        "generated_at": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings]
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    return output_file
