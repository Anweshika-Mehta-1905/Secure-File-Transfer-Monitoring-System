#!/usr/bin/env python3
"""Self-contained demonstration: builds a sandbox, starts the REAL watchdog monitor and
performs ten attack / normal-use scenarios. Produces logs/, reports/ and integrity evidence.

    python demo.py [--workspace ./demo_workspace]

Actor names (alice, intern01, ...) and process names are supplied by the demo through
`engine.actor_hints` so the log shows who did what; on a real system the user comes from the OS
and the process from psutil.
"""
import argparse
import json
import os
import shutil
import time

from sftms.config import load_config
from sftms.engine import Engine
from sftms.logger import AuditLogger
from sftms.monitor import start_observer
from sftms.report import verify_baseline, write_report

PAUSE = 1.2


def w(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data if isinstance(data, bytes) else data.encode())


def banner(n, text):
    print(f"\n=== Scenario {n}: {text} ===")
    time.sleep(0.3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_workspace"))
    a = ap.parse_args()
    ws = os.path.abspath(a.workspace)
    here = os.path.dirname(os.path.abspath(__file__))
    shutil.rmtree(ws, ignore_errors=True)
    for d in ("logs", "reports"):
        shutil.rmtree(os.path.join(here, d), ignore_errors=True)

    P = lambda *x: os.path.join(ws, *x)
    conf = P("Documents", "Confidential")
    cfg_path = os.path.join(here, "demo_config.json")
    with open(cfg_path, "w") as fh:
        json.dump({
            "watch_dirs": [ws],  # one watch root so cross-folder moves arrive as MOVE events
            "sensitive_dirs": [conf],
            "sensitive_extensions": [".pem", ".key", ".pfx", ".kdbx", ".sql"],
            "sensitive_keywords": ["password", "confidential", "secret", "salary", "payroll"],
            "authorized_users": ["admin", "alice"],
            "allowed_destinations": [conf, P("Documents", "Archive")],
            "removable_prefixes": [P("USB_E")],
            "network_prefixes": ["//", "\\\\", P("NetShare")],
            "cloud_folder_names": ["Dropbox", "OneDrive", "CloudSync"],
            "hash_algorithm": "sha256", "bulk_threshold": 50, "bulk_window_seconds": 60,
            "log_dir": "logs", "report_dir": "reports"}, fh, indent=2)

    # ---- seed files ----
    w(P("Documents", "Confidential", "salary_2026.csv"), "id,name,salary\n1,A,90000\n2,B,85000\n3,C,120000\n")
    w(P("Documents", "Confidential", "customer_db.sql"), "INSERT INTO customers VALUES (1,'Acme','acme@example.com');\n" * 50)
    w(P("Documents", "Confidential", "server_private.key"), "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B...\n-----END PRIVATE KEY-----\n")
    w(P("Documents", "Projects", "notes.txt"), "Sprint planning notes\n" * 20)
    w(P("Documents", "Projects", "report.docx"), os.urandom(4096))
    w(P("Documents", "Projects", "budget_draft.txt"), "draft numbers\n" * 30)
    for d in ("Archive", "Public"):
        os.makedirs(P("Documents", d), exist_ok=True)
    for d in ("USB_E", "CloudSync/Dropbox", "Downloads/unknown_dir", "Staging", "NetShare"):
        os.makedirs(P(*d.split("/")), exist_ok=True)

    cfg = load_config(cfg_path)
    log = AuditLogger(cfg["log_dir"])
    eng = Engine(cfg, log)
    n = eng.baseline.scan(cfg["watch_dirs"])
    eng.baseline.save()
    print(f"[SETUP] Baseline created: {n} files hashed with SHA-256")
    observer, watcher = start_observer(eng, usb=False)
    print("[SETUP] Monitoring started on:", ", ".join(os.path.relpath(d, ws) for d in cfg["watch_dirs"]))
    time.sleep(1)

    def hint(path, user, proc):
        eng.actor_hints[path] = (user, proc)

    banner(1, "Normal activity - alice copies a project note to Public")
    d = P("Documents", "Public", "notes.txt"); hint(d, "alice", "explorer.exe")
    shutil.copy2(P("Documents", "Projects", "notes.txt"), d); time.sleep(PAUSE)

    banner(2, "Authorised handling - alice archives the customer database")
    d = P("Documents", "Archive", "customer_db.sql"); hint(d, "alice", "robocopy.exe")
    shutil.copy2(P("Documents", "Confidential", "customer_db.sql"), d); time.sleep(PAUSE)

    banner(3, "Insider threat - intern01 copies salary file to USB drive")
    d = P("USB_E", "salary_2026.csv"); hint(d, "intern01", "explorer.exe")
    shutil.copy2(P("Documents", "Confidential", "salary_2026.csv"), d); time.sleep(PAUSE)

    banner(4, "Exfiltration - bob syncs a private key to Dropbox")
    d = P("CloudSync", "Dropbox", "server_private.key"); hint(d, "bob", "Dropbox.exe")
    shutil.copy2(P("Documents", "Confidential", "server_private.key"), d); time.sleep(PAUSE)

    banner(5, "Unapproved move - admin moves a sensitive file to Staging")
    s = P("Documents", "Confidential", "customer_db.sql"); d = P("Staging", "customer_db.sql"); hint(d, "admin", "mv")
    shutil.move(s, d); time.sleep(PAUSE)

    banner(6, "Tampering - malware appends bytes to the private key")
    t = P("Documents", "Confidential", "server_private.key"); hint(t, "SYSTEM", "unknown_dropper.exe")
    with open(t, "ab") as fh:
        fh.write(b"\n#injected-by-malware\n")
    time.sleep(PAUSE)

    banner(7, "Corrupted transfer - report.docx altered while copied to Public")
    d = P("Documents", "Public", "report.docx"); hint(d, "alice", "unknown_sync_tool")
    data = bytearray(open(P("Documents", "Projects", "report.docx"), "rb").read()); data[100] ^= 0xFF
    w(d, bytes(data)); time.sleep(PAUSE)

    banner(8, "Non-sensitive file to USB - alice copies a draft")
    d = P("USB_E", "budget_draft.txt"); hint(d, "alice", "explorer.exe")
    shutil.copy2(P("Documents", "Projects", "budget_draft.txt"), d); time.sleep(PAUSE)

    banner(9, "Bulk transfer - 200 files dumped into an unknown directory")
    bulk = P("Downloads", "unknown_dir")
    for i in range(200):
        f = os.path.join(bulk, f"dump_{i:03d}.dat"); hint(f, "bob", "rclone")
        w(f, os.urandom(256) + str(i).encode())
    for _ in range(100):                      # wait for the event queue to drain
        if sum(1 for p in eng.baseline.data if "dump_" in p) >= 200:
            break
        time.sleep(0.3)
    time.sleep(1)

    banner(10, "Cleanup attempt - intern01 deletes the archived database copy")
    t = P("Documents", "Archive", "customer_db.sql"); hint(t, "intern01", "del.exe")
    os.remove(t); time.sleep(PAUSE)

    time.sleep(1)
    observer.stop(); observer.join()
    eng.baseline.save()

    print("\n=== Scenario 11: Monitor stopped - salary file silently altered offline ===")
    with open(P("Documents", "Confidential", "salary_2026.csv"), "a") as fh:
        fh.write("4,Mallory,999999\n")

    print("\n=== Offline integrity verification (re-hash all tracked files) ===")
    rows, bad, out = verify_baseline(cfg, eng.baseline)
    print(f"Verified {len(rows)} files; {bad} problem(s).")
    for r in rows:
        if r[3] != "MATCH":
            print(f"  [{r[3]}] {r[0]}")
    s = write_report(cfg)
    print(f"\n[REPORT] {s['total_events']} events | {s['total_alerts']} alerts | "
          f"integrity: {s['integrity_match']} match / {s['integrity_mismatch']} mismatch")
    print(f"[REPORT] See reports/audit_report.md and reports/audit_report.html")


if __name__ == "__main__":
    main()
