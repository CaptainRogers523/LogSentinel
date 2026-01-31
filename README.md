# LogSentinel 🛡️

LogSentinel is a security-focused log analysis tool that detects attack patterns
such as brute force, SQL injection, XSS, and path traversal from web server logs.

## Features
- Brute Force Detection
- SQL Injection Detection
- XSS Detection
- Path Traversal Detection
- Severity Scoring (Low → Critical)
- Deduplication of findings
- JSON & Markdown reports
- CLI support

## Usage

```bash
python logsentinel.py --log samples/access.log --json --md


Output

Reports are generated in:

LogSentinel/reports/

Author

Built by Captain Rogers


🔥 Enough for v1.0. Don’t overthink.

---

## 🧠 STEP 3 — Initialize Git

```powershell
git init
git status