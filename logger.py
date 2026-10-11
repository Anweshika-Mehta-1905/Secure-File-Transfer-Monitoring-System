"""STEP 5 - audit logging and alerting (JSONL + text alert log + integrity CSV)."""
import csv
import json
import os
import threading
from datetime import datetime

COLORS = {"INFO": "\033[32m", "WARNING": "\033[33m", "HIGH": "\033[91m", "CRITICAL": "\033[1;31m"}
RESET = "\033[0m"


class AuditLogger:
    def __init__(self, log_dir, console=True):
        self.console = console
        self.lock = threading.Lock()
        self.events_path = os.path.join(log_dir, "file_transfer.log.jsonl")
        self.alerts_path = os.path.join(log_dir, "alerts.log")
        self.integrity_path = os.path.join(log_dir, "integrity_checks.csv")
        if not os.path.exists(self.integrity_path):
            with open(self.integrity_path, "w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerow(["timestamp", "file", "context", "pre_hash", "post_hash", "result"])

    @staticmethod
    def now():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def event(self, record, alert=None):
        record = {"timestamp": self.now(), **record}
        if alert:
            record["alert"] = alert
        with self.lock:
            with open(self.events_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
            if alert:
                with open(self.alerts_path, "a", encoding="utf-8") as fh:
                    fh.write(f"{record['timestamp']} [{alert['severity']}] {alert['type']}: "
                             f"{alert['message']} | user={record.get('user')} proc={record.get('process')}\n")
        if self.console:
            sev = alert["severity"] if alert else "INFO"
            tag = f"{COLORS[sev]}[{sev}]{RESET}"
            msg = alert["message"] if alert else f"{record['event']} {record.get('src') or ''} -> {record.get('dest') or ''}"
            print(f"{record['timestamp']} {tag} {msg}")

    def integrity(self, file, context, pre, post):
        result = "MATCH" if pre == post else "MISMATCH"
        with self.lock:
            with open(self.integrity_path, "a", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerow([self.now(), file, context, pre, post, result])
        return result
