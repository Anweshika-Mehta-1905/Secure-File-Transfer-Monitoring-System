"""STEP 6 - final audit report (Markdown + HTML + JSON summary) and offline integrity verification."""
import csv
import html
import json
import os
from collections import Counter
from datetime import datetime

from .hasher import hash_file


def _load(log_dir):
    events = []
    p = os.path.join(log_dir, "file_transfer.log.jsonl")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            events = [json.loads(line) for line in fh if line.strip()]
    integrity = []
    ip = os.path.join(log_dir, "integrity_checks.csv")
    if os.path.exists(ip):
        with open(ip, encoding="utf-8") as fh:
            integrity = list(csv.DictReader(fh))
    return events, integrity


def summarize(cfg):
    events, integrity = _load(cfg["log_dir"])
    alerts = [e for e in events if e.get("alert")]
    s = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_events": len(events),
        "by_event": dict(Counter(e["event"] for e in events)),
        "total_alerts": len(alerts),
        "by_severity": dict(Counter(e["alert"]["severity"] for e in alerts)),
        "by_alert_type": dict(Counter(e["alert"]["type"] for e in alerts)),
        "by_user": dict(Counter(e.get("user", "?") for e in events)),
        "sensitive_events": sum(1 for e in events if e.get("sensitive")),
        "integrity_checks": len(integrity),
        "integrity_match": sum(1 for r in integrity if r["result"] == "MATCH"),
        "integrity_mismatch": sum(1 for r in integrity if r["result"] == "MISMATCH"),
    }
    return s, events, alerts, integrity


def write_report(cfg):
    s, events, alerts, integrity = summarize(cfg)
    out = cfg["report_dir"]
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "summary.json"), "w") as fh:
        json.dump(s, fh, indent=2)

    def table(rows, head):
        lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
        return "\n".join(lines)

    md = [f"# Secure File Transfer Monitoring System - Final Audit Report",
          f"_Generated: {s['generated']}_\n",
          "## 1. Executive Summary",
          f"- Total file events logged: **{s['total_events']}**",
          f"- Events involving sensitive files: **{s['sensitive_events']}**",
          f"- Alerts raised: **{s['total_alerts']}**",
          f"- Integrity checks: **{s['integrity_checks']}** ({s['integrity_match']} match, **{s['integrity_mismatch']} mismatch**)\n",
          "## 2. Activity by Event Type",
          table(sorted(s["by_event"].items()), ["Event", "Count"]), "",
          "## 3. Alerts by Severity",
          table(sorted(s["by_severity"].items(), key=lambda x: -["INFO", "WARNING", "HIGH", "CRITICAL"].index(x[0])), ["Severity", "Count"]), "",
          "## 4. Alerts by Type",
          table(sorted(s["by_alert_type"].items(), key=lambda x: -x[1]), ["Alert type", "Count"]), "",
          "## 5. Activity by User",
          table(sorted(s["by_user"].items(), key=lambda x: -x[1]), ["User", "Events"]), "",
          "## 6. Alert Details",
          table([(a["timestamp"], a["alert"]["severity"], a["alert"]["type"], a["alert"]["message"], a.get("user"))
                 for a in alerts], ["Time", "Severity", "Type", "Message", "User"]), "",
          "## 7. Integrity Verification Results",
          table([(r["timestamp"], os.path.basename(r["file"]), r["context"][:40], r["pre_hash"][:12] + "...",
                  (r["post_hash"] or "")[:12] + "...", r["result"]) for r in integrity],
                ["Time", "File", "Context", "Pre-hash", "Post-hash", "Result"]), "",
          "## 8. Conclusion",
          ("Policy violations were detected and should be investigated by the security team."
           if s["total_alerts"] else "No policy violations were detected in the monitored period.")]
    text = "\n".join(md)
    with open(os.path.join(out, "audit_report.md"), "w", encoding="utf-8") as fh:
        fh.write(text)
    # simple HTML rendering
    body = []
    for line in text.splitlines():
        if line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("|"):
            if set(line.replace("|", "").strip()) <= {"-"}:
                continue
            cells = [html.escape(c.strip()) for c in line.strip("|").split("|")]
            tag = "th" if (not body or not body[-1].startswith("<tr")) and body and body[-1].startswith("<h2") else "td"
            body.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
        elif line.strip():
            body.append(f"<p>{html.escape(line)}</p>")
    css = "body{font-family:Arial;margin:30px}table{border-collapse:collapse;margin:8px 0}td,th{border:1px solid #bbb;padding:4px 8px;font-size:13px}th{background:#1F3A5F;color:#fff}h2{color:#1F3A5F}"
    with open(os.path.join(out, "audit_report.html"), "w", encoding="utf-8") as fh:
        fh.write(f"<html><head><meta charset='utf-8'><style>{css}</style></head><body>{''.join(body)}</body></html>")
    return s


def verify_baseline(cfg, store):
    """Re-hash every tracked file and compare to its trusted baseline hash."""
    rows, bad = [], 0
    for path, meta in sorted(store.data.items()):
        now = hash_file(path, cfg["hash_algorithm"])
        res = "MISSING" if now is None else ("MATCH" if now == meta["hash"] else "MISMATCH")
        bad += res != "MATCH"
        rows.append([path, meta["hash"], now or "", res])
    out = os.path.join(cfg["report_dir"], "integrity_verification.csv")
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["file", "baseline_hash", "current_hash", "result"])
        w.writerows(rows)
    return rows, bad, out
