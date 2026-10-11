#!/usr/bin/env python3
"""Secure File Transfer Monitoring System - command line interface.

  python main.py baseline            # hash all watched files (trusted baseline)
  python main.py monitor             # live monitoring (Ctrl+C to stop, report is written)
  python main.py verify              # re-hash baseline files and report tampering
  python main.py report              # build the audit report from existing logs
"""
import argparse
import time

from sftms.config import load_config
from sftms.engine import Engine
from sftms.logger import AuditLogger
from sftms.monitor import start_observer
from sftms.report import verify_baseline, write_report


def main():
    ap = argparse.ArgumentParser(description="Secure File Transfer Monitoring System")
    ap.add_argument("command", choices=["baseline", "monitor", "verify", "report"])
    ap.add_argument("-c", "--config", default="config.json")
    ap.add_argument("--no-usb", action="store_true", help="disable USB insertion watcher")
    args = ap.parse_args()

    cfg = load_config(args.config)
    log = AuditLogger(cfg["log_dir"])
    engine = Engine(cfg, log)

    if args.command == "baseline":
        n = engine.baseline.scan(cfg["watch_dirs"] + cfg["sensitive_dirs"])
        engine.baseline.save()
        print(f"Baseline created: {n} files hashed ({cfg['hash_algorithm']}).")
    elif args.command == "monitor":
        if not engine.baseline.data:
            n = engine.baseline.scan(cfg["watch_dirs"] + cfg["sensitive_dirs"])
            print(f"No baseline found - hashed {n} files.")
        observer, watcher = start_observer(engine, usb=not args.no_usb)
        print("Monitoring started. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        observer.stop(); observer.join()
        engine.baseline.save()
        write_report(cfg)
        print(f"Stopped. Report written to {cfg['report_dir']}")
    elif args.command == "verify":
        rows, bad, out = verify_baseline(cfg, engine.baseline)
        print(f"Verified {len(rows)} files, {bad} problem(s). Details: {out}")
        for r in rows:
            if r[3] != "MATCH":
                print(f"  [{r[3]}] {r[0]}")
    else:
        s = write_report(cfg)
        print(f"Report written: {s['total_events']} events, {s['total_alerts']} alerts.")


if __name__ == "__main__":
    main()
