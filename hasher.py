"""File hashing and the baseline (trusted hash) store."""
import hashlib
import json
import os
import time

CHUNK = 1024 * 1024


def hash_file(path, algo="sha256"):
    """Return hex digest of a file, or None if unreadable."""
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(CHUNK), b""):
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


class BaselineStore:
    """path -> {hash, size, mtime}. Persisted as JSON; also keeps hash->paths index."""

    def __init__(self, path, algo="sha256"):
        self.path, self.algo = path, algo
        self.data = {}
        self.by_hash = {}   # digest -> set(paths)   (fast copy detection)
        self.by_name = {}   # basename -> set(paths) (altered-copy detection)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                self.data = json.load(fh)
            for p, meta in self.data.items():
                self._index(p, meta["hash"])

    def _index(self, p, digest):
        self.by_hash.setdefault(digest, set()).add(p)
        self.by_name.setdefault(os.path.basename(p), set()).add(p)

    def _unindex(self, p):
        meta = self.data.get(p)
        if meta:
            self.by_hash.get(meta["hash"], set()).discard(p)
            self.by_name.get(os.path.basename(p), set()).discard(p)

    def find_by_name(self, filepath):
        for p in self.by_name.get(os.path.basename(filepath), ()):
            if p != filepath and os.path.exists(p):
                return p
        return None

    def record(self, filepath, digest=None):
        digest = digest or hash_file(filepath, self.algo)
        if digest is None:
            return None
        st = os.stat(filepath)
        self._unindex(filepath)
        self._index(filepath, digest)
        self.data[filepath] = {"hash": digest, "size": st.st_size, "mtime": st.st_mtime}
        return digest

    def get(self, filepath):
        return self.data.get(filepath)

    def remove(self, filepath):
        self._unindex(filepath)
        return self.data.pop(filepath, None)

    def find_by_hash(self, digest, exclude=None):
        """Return an existing tracked path with identical content (copy detection)."""
        for p in self.by_hash.get(digest, ()):
            if p != exclude and os.path.exists(p):
                return p
        return None

    def scan(self, directories):
        count = 0
        for root_dir in directories:
            for root, _dirs, files in os.walk(root_dir):
                for name in files:
                    if self.record(os.path.join(root, name)):
                        count += 1
        return count

    def save(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2)
