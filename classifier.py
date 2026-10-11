"""STEP 2 - classify files (sensitive/normal) and destinations (zones)."""
import os


def _norm(p):
    return os.path.normcase(os.path.abspath(p)) if p and not p.startswith(("\\\\", "//")) else (p or "")


def _under(path, prefix):
    path, prefix = _norm(path), _norm(prefix)
    return path == prefix or path.startswith(prefix.rstrip(os.sep) + os.sep)


class Classifier:
    def __init__(self, cfg):
        self.cfg = cfg

    def sensitivity(self, path):
        """Return list of reasons the file is sensitive (empty list = normal)."""
        reasons = []
        for d in self.cfg["sensitive_dirs"]:
            if _under(path, d):
                reasons.append("in sensitive directory")
                break
        name = os.path.basename(path).lower()
        ext = os.path.splitext(name)[1]
        if ext in [e.lower() for e in self.cfg["sensitive_extensions"]]:
            reasons.append(f"sensitive extension {ext}")
        for kw in self.cfg["sensitive_keywords"]:
            if kw.lower() in name:
                reasons.append(f"keyword '{kw}'")
                break
        return reasons

    def zone(self, path):
        """Classify a destination: removable | network | cloud | allowed | internal."""
        p = path or ""
        for pre in self.cfg["removable_prefixes"]:
            if _under(p, pre) or p.upper().startswith(pre.upper()):
                return "removable"
        for pre in self.cfg["network_prefixes"]:
            if pre in ("//", "\\\\"):            # UNC style paths: \\\\server\\share or //server/share
                if p.startswith(pre):
                    return "network"
            elif _under(p, pre):
                return "network"
        parts = [x.lower() for x in p.replace("\\", "/").split("/")]
        for cloud in self.cfg["cloud_folder_names"]:
            if cloud.lower() in parts:
                return "cloud"
        for d in self.cfg["allowed_destinations"]:
            if _under(p, d):
                return "allowed"
        return "internal"
