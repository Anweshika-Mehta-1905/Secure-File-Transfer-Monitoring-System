# Secure File Transfer Monitoring System (SFTMS)

Python toolkit that logs file transfers, detects unauthorised movement of sensitive files,
verifies integrity with SHA-256, raises graded alerts and produces an audit report.

## Folder contents
| Folder | Contents |
|---|---|
| `toolkit/` | Source code: `main.py` (CLI), `demo.py` (test harness), `config.json`, `sftms/` modules |
| `toolkit/sample_output/` | Logs and reports from a real demo run (alerts.log, JSONL audit log, integrity CSV, audit_report.md/.html) |
| `diagrams/` | Architecture diagram and detection flowchart (PNG) |
| `evidence/` | Terminal-style captures of the demo output (monitoring, alerts, integrity, verification) |
| `documentation/` | Project report as Word and PDF |
| `presentation/` | Final presentation (PowerPoint) |

## Quick start
```bash
cd toolkit
pip install -r requirements.txt
python demo.py                  # runs 11 scenarios in a sandbox; writes logs/ and reports/
```
Open `reports/audit_report.html` afterwards.

## Monitor your own folders
1. Edit `toolkit/config.json`: `watch_dirs`, `sensitive_dirs`, `authorized_users`, `allowed_destinations`,
   and `removable_prefixes` (for example `E:\\` on Windows, `/media` on Linux).
2. Run:
```bash
python main.py baseline    # hash all watched files (trusted reference)
python main.py monitor     # live monitoring; Ctrl+C stops and writes the report
python main.py verify      # re-hash and report tampered or missing files
python main.py report      # rebuild the report from existing logs
```
Keep `log_dir` outside every folder in `watch_dirs`.

## Taking real screenshots for submission
Run `python demo.py` (or `python main.py monitor` while copying files to a test USB folder) and capture the
terminal, `logs/alerts.log`, `logs/integrity_checks.csv` and `reports/audit_report.html`.
The PNGs in `evidence/` are renderings of real output from the included run.

## Notes
- The demo labels actors (alice, intern01, bob) through `engine.actor_hints`. In real use the user comes from the OS and the
  process name from psutil (best effort).
- watchdog does not report file reads; read-access auditing needs OS auditing (auditd / Windows Event 4663).
- Use only on systems you own or are authorised to monitor.
