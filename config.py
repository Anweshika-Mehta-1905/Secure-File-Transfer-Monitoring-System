"""Configuration loader with safe defaults."""
import json
import os

DEFAULTS = {
    "watch_dirs": [],
    "sensitive_dirs": [],
    "sensitive_extensions": [".pem", ".key", ".pfx", ".kdbx"],
    "sensitive_keywords": ["password", "confidential", "secret", "salary"],
    "authorized_users": [],
    "allowed_destinations": [],
    "removable_prefixes": [],
    "network_prefixes": [],
    "cloud_folder_names": ["Dropbox", "OneDrive", "Google Drive"],
    "hash_algorithm": "sha256",
    "bulk_threshold": 50,
    "bulk_window_seconds": 60,
    "log_dir": "logs",
    "report_dir": "reports",
}


def load_config(path="config.json"):
    cfg = dict(DEFAULTS)
    with open(path, "r", encoding="utf-8") as fh:
        cfg.update({k: v for k, v in json.load(fh).items() if not k.startswith("_")})
    base = os.path.dirname(os.path.abspath(path))
    for key in ("log_dir", "report_dir"):
        if not os.path.isabs(cfg[key]):
            cfg[key] = os.path.join(base, cfg[key])
        os.makedirs(cfg[key], exist_ok=True)
    return cfg
