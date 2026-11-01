"""Offline secret-pattern review with redacted output. Python 3.9+ standard library."""
import argparse
import hashlib
import html
import json
import os
import re
import sys
from pathlib import Path

RULES = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "high"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b"), "high"),
    ("aws-access-id", re.compile(r"\bAKIA[A-Z0-9]{16}\b"), "medium"),
    ("credential-assignment", re.compile(r"""(?i)\b(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*["']([^"'\r\n]{16,200})["']"""), "medium"),
]
EXCLUDED = {".git", ".venv", "venv", "node_modules", "__pycache__", "data", "reports", "target", "bin", "obj"}
MAX_BYTES = 1024 * 1024

def scan(root, max_bytes=MAX_BYTES):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("Input must be a directory")
    findings, skipped, errors = [], 0, 0
    def walk_error(_):
        nonlocal errors
        errors += 1
    checked = 0
    for directory, folders, names in os.walk(root, followlinks=False, onerror=walk_error):
        folders[:] = sorted(n for n in folders if n not in EXCLUDED and not (Path(directory) / n).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_symlink():
                skipped += 1
                continue
            try:
                if path.stat().st_size > max_bytes:
                    skipped += 1
                    continue
                raw = path.read_bytes()
                if b"\0" in raw:
                    skipped += 1
                    continue
                text = raw.decode("utf-8")
                checked += 1
                for line_number, line in enumerate(text.splitlines(), 1):
                    for rule, pattern, severity in RULES:
                        for match in pattern.finditer(line):
                            value = match.group(1) if match.lastindex else match.group(0)
                            findings.append({
                                "path": path.relative_to(root).as_posix(),
                                "line": line_number,
                                "rule": rule,
                                "severity": severity,
                                "fingerprint": hashlib.sha256(value.encode()).hexdigest()[:16],
                            })
            except UnicodeDecodeError:
                skipped += 1
            except OSError:
                errors += 1
    return {"version": 1, "files_checked": checked, "files_skipped": skipped, "read_errors": errors, "findings": findings}

def render(report):
    rows = "".join("<tr>" + "".join("<td>" + html.escape(str(f[k])) + "</td>" for k in ["path", "line", "rule", "severity", "fingerprint"]) + "</tr>" for f in report["findings"])
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Secret Sentinel report</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px;color:#163044;background:#f4f8fb}table{width:100%;border-collapse:collapse;background:white}td,th{padding:12px;text-align:left;border-bottom:1px solid #ddd}h1{color:#12665f}</style><h1>Secret Sentinel</h1><p>Offline pattern review. Values are redacted; findings require manual review.</p><p>Files checked: ' + str(report["files_checked"]) + ' · Findings: ' + str(len(report["findings"])) + ' · Read errors: ' + str(report["read_errors"]) + '</p><table><tr><th>Path</th><th>Line</th><th>Rule</th><th>Severity</th><th>Fingerprint</th></tr>' + rows + '</table></html>'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--html", dest="html_path")
    args = parser.parse_args()
    try:
        report = scan(args.directory)
        if args.json_path:
            Path(args.json_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        if args.html_path:
            Path(args.html_path).write_text(render(report), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 2 if report["read_errors"] else (1 if report["findings"] else 0)
    except (ValueError, OSError) as error:
        print("Unable to complete scan: " + str(error), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
