"""STEP 1 - filesystem monitoring with watchdog (+ optional USB-insert watcher)."""
import os
import threading
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class TransferHandler(FileSystemEventHandler):
    def __init__(self, engine):
        self.engine = engine

    def on_created(self, e):
        if not e.is_directory:
            self.engine.on_created(e.src_path)

    def on_modified(self, e):
        if not e.is_directory:
            self.engine.on_modified(e.src_path)

    def on_deleted(self, e):
        if not e.is_directory:
            self.engine.on_deleted(e.src_path)

    def on_moved(self, e):
        if not e.is_directory:
            self.engine.on_moved(e.src_path, e.dest_path)


class UsbWatcher(threading.Thread):
    """Polls psutil for newly mounted removable drives and watches them too."""

    def __init__(self, observer, handler, engine, interval=5):
        super().__init__(daemon=True)
        self.observer, self.handler, self.engine, self.interval = observer, handler, engine, interval
        self.known = set()
        self.running = True

    def run(self):
        try:
            import psutil
        except ImportError:
            return
        while self.running:
            for part in psutil.disk_partitions(all=False):
                removable = "removable" in part.opts.lower() or part.mountpoint.startswith(("/media", "/run/media", "/Volumes"))
                if removable and part.mountpoint not in self.known:
                    self.known.add(part.mountpoint)
                    if part.mountpoint not in self.engine.cfg["removable_prefixes"]:
                        self.engine.cfg["removable_prefixes"].append(part.mountpoint)
                    self.observer.schedule(self.handler, part.mountpoint, recursive=True)
                    self.engine.log.event({"event": "USB_MOUNTED", "dest": part.mountpoint, "user": "system", "process": "psutil"})
            time.sleep(self.interval)


def start_observer(engine, usb=True):
    observer, handler = Observer(), TransferHandler(engine)
    for d in engine.cfg["watch_dirs"]:
        if os.path.isdir(d):
            observer.schedule(handler, d, recursive=True)
    observer.start()
    watcher = None
    if usb:
        watcher = UsbWatcher(observer, handler, engine)
        watcher.start()
    return observer, watcher
