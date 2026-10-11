"""Core detection engine: implements Steps 2-5 of the workflow.

    classify -> integrity hash -> authorization check -> log / alert
"""
import getpass
import os
import threading
import time
from collections import defaultdict, deque

from .classifier import Classifier, _under
from .hasher import BaselineStore, hash_file

VERB = {"COPY": "copied", "MOVE": "moved", "CREATE": "created"}
SEV_RANK = {"INFO": 0, "WARNING": 1, "HIGH": 2, "CRITICAL": 3}


def wait_stable(path, tries=10, delay=0.01):
    """Wait until a file stops growing (copy finished) before hashing it."""
    last = -1
    for _ in range(tries):
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
        if size == last:
            return True
        last = size
        time.sleep(delay)
    return True


def process_for(paths):
    """Best-effort process attribution via psutil (optional)."""
    try:
        import psutil
    except ImportError:
        return "unknown"
    try:
        for proc in psutil.process_iter(["name", "cmdline"]):
            cmd = " ".join(proc.info.get("cmdline") or [])
            if any(p and p in cmd for p in paths):
                return proc.info["name"]
        for proc in psutil.process_iter(["name"]):
            try:
                if any(f.path in paths for f in proc.open_files()):
                    return proc.info["name"]
            except (psutil.Error, OSError):
                continue
    except Exception:
        pass
    return "unknown"


class Engine:
    def __init__(self, cfg, logger):
        self.cfg, self.log = cfg, logger
        self.cls = Classifier(cfg)
        self.algo = cfg["hash_algorithm"]
        self.baseline = BaselineStore(os.path.join(cfg["log_dir"], "baseline.json"), self.algo)
        self.lock = threading.RLock()
        self.actor_hints = {}   # path -> (user, process); used by the demo to label actors
        self.bulk = defaultdict(deque)
        self.bulk_alerted = {}

    # ---------- helpers ----------
    def actor(self, *paths):
        for p in paths:
            if p in self.actor_hints:
                return self.actor_hints[p]
        return getpass.getuser(), process_for([p for p in paths if p])

    def _is_authorized_user(self, user):
        return user in self.cfg["authorized_users"]

    def _allowed_dest(self, dest):
        return any(_under(dest, d) for d in self.cfg["allowed_destinations"] + self.cfg["sensitive_dirs"])

    @staticmethod
    def _worst(alerts):
        return max(alerts, key=lambda a: SEV_RANK[a["severity"]]) if alerts else None

    # ---------- STEP 4: authorization check ----------
    def authorize(self, ev, src, dest, user):
        reasons = self.cls.sensitivity(src) if src else []
        reasons = reasons or self.cls.sensitivity(dest)
        zone = self.cls.zone(dest)
        alerts = []
        if reasons:
            if zone == "removable":
                alerts.append(("SENSITIVE_TO_USB", "CRITICAL", f"Sensitive file {VERB.get(ev, ev.lower())} to USB drive: {os.path.basename(dest)} -> {dest}"))
            elif zone == "cloud":
                alerts.append(("SENSITIVE_TO_CLOUD", "CRITICAL", f"Sensitive file {VERB.get(ev, ev.lower())} to cloud-sync folder: {dest}"))
            elif zone == "network":
                alerts.append(("SENSITIVE_TO_NETWORK", "HIGH", f"Sensitive file {VERB.get(ev, ev.lower())} to network share: {dest}"))
            elif ev in ("COPY", "MOVE") and not self._allowed_dest(dest):
                alerts.append(("UNAUTHORIZED_MOVEMENT", "HIGH", f"Sensitive file {VERB.get(ev, ev.lower())} to unapproved location: {dest}"))
            if not self._is_authorized_user(user):
                alerts.append(("UNAUTHORIZED_USER", "HIGH", f"User '{user}' is not authorised to handle sensitive file {os.path.basename(dest)}"))
        elif zone in ("removable", "cloud", "network"):
            alerts.append(("SUSPICIOUS_OUTBOUND", "WARNING", f"Outbound transfer to {zone} location: {dest}"))
        return reasons, zone, self._worst([{"type": t, "severity": s, "message": m} for t, s, m in alerts]), alerts

    # ---------- bulk transfer detection ----------
    def _bulk_check(self, dest):
        d = os.path.dirname(dest)
        now, win = time.time(), self.cfg["bulk_window_seconds"]
        q = self.bulk[d]
        q.append(now)
        while q and now - q[0] > win:
            q.popleft()
        if len(q) >= self.cfg["bulk_threshold"] and now - self.bulk_alerted.get(d, 0) > win and not self._allowed_dest(d):
            self.bulk_alerted[d] = now
            alert = {"type": "SUSPICIOUS_BULK_TRANSFER", "severity": "HIGH",
                     "message": f"{len(q)} files transferred to unknown directory '{d}' within {win}s"}
            self.log.event({"event": "BULK_TRANSFER", "dest": d, "count": len(q), "user": getpass.getuser(),
                            "process": "n/a"}, alert)

    # ---------- event handlers ----------
    def on_created(self, path):
        if os.path.isdir(path) or not wait_stable(path):
            return
        with self.lock:
            post = hash_file(path, self.algo)
            if post is None:
                return
            src = self.baseline.find_by_hash(post, exclude=path)
            ev, pre, note = "CREATE", None, None
            if src:
                ev, pre = "COPY", post          # identical content elsewhere => copy
            else:                               # name match + different content => altered copy
                cand = self.baseline.find_by_name(path)
                if cand:
                    ev, src, pre = "COPY", cand, hash_file(cand, self.algo)
            user, proc = self.actor(path, src)
            self._transfer(ev, src, path, pre, post, user, proc)
            self.baseline.record(path, post)

    def on_moved(self, src, dest):
        if os.path.isdir(dest) or not wait_stable(dest):
            return
        with self.lock:
            meta = self.baseline.remove(src)
            pre = meta["hash"] if meta else None
            post = hash_file(dest, self.algo)
            user, proc = self.actor(dest, src)
            self._transfer("MOVE", src, dest, pre, post, user, proc)
            if post:
                self.baseline.record(dest, post)

    def on_modified(self, path):
        if os.path.isdir(path):
            return
        with self.lock:
            meta = self.baseline.get(path)
            if not meta:
                return
            post = hash_file(path, self.algo)
            if post is None or post == meta["hash"]:
                return
            wait_stable(path)
            post = hash_file(path, self.algo)
            reasons = self.cls.sensitivity(path)
            user, proc = self.actor(path)
            rec = {"event": "MODIFY", "src": path, "dest": None, "user": user, "process": proc,
                   "sensitive": bool(reasons), "pre_hash": meta["hash"], "post_hash": post}
            if reasons:
                self.log.integrity(path, "modification of sensitive file", meta["hash"], post)
                rec["integrity"] = "MISMATCH"
                self.log.event(rec, {"type": "INTEGRITY_FAILURE", "severity": "HIGH",
                                     "message": f"File hash mismatch detected: {path}"})
            else:
                rec["integrity"] = "CHANGED"
                self.log.event(rec)
            self.baseline.record(path, post)

    def on_deleted(self, path):
        with self.lock:
            meta = self.baseline.remove(path)
            reasons = self.cls.sensitivity(path)
            user, proc = self.actor(path)
            rec = {"event": "DELETE", "src": path, "dest": None, "user": user, "process": proc,
                   "sensitive": bool(reasons), "pre_hash": meta["hash"] if meta else None}
            alert = None
            if reasons:
                sev = "WARNING" if self._is_authorized_user(user) else "HIGH"
                alert = {"type": "SENSITIVE_DELETED", "severity": sev, "message": f"Sensitive file deleted: {path}"}
            self.log.event(rec, alert)

    # ---------- shared transfer pipeline (Steps 3-5) ----------
    def _transfer(self, ev, src, dest, pre, post, user, proc):
        reasons, zone, alert, all_alerts = self.authorize(ev, src, dest, user)
        rec = {"event": ev, "src": src, "dest": dest, "user": user, "process": proc,
               "sensitive": bool(reasons), "sensitivity_reasons": reasons, "dest_zone": zone,
               "size": os.path.getsize(dest) if os.path.exists(dest) else None,
               "pre_hash": pre, "post_hash": post}
        if pre is not None:                                   # STEP 3: integrity
            result = self.log.integrity(dest, f"{ev.lower()} from {src}", pre, post)
            rec["integrity"] = result
            if result == "MISMATCH":
                sev = "CRITICAL" if reasons else "HIGH"
                self.log.event(rec, {"type": "INTEGRITY_FAILURE", "severity": sev,
                                     "message": f"File hash mismatch detected after {ev.lower()}: {dest}"})
                self._bulk_check(dest)
                return
        if alert:
            rec["all_alert_types"] = [a[0] for a in all_alerts]
        self.log.event(rec, alert)
        if ev in ("COPY", "MOVE", "CREATE"):
            self._bulk_check(dest)
