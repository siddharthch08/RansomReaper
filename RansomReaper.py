#!/usr/bin/env python3
\"\"\"smart_ransom_detector.py

Hybrid ransomware early detector: heuristics-driven CLI & Tkinter GUI.

Features:
- Watch specified folders using watchdog
- Heuristics: event-rate, extension-change, entropy checks, honeypot trigger
- Best-effort process mapping via psutil
- Optional auto-quarantine and auto-kill (OFF by default)
- Tkinter GUI with Start/Stop and live logs (runs headless if no GUI)
- Safe-by-default: only alerts unless user enables active responses
\"\"\"
import argparse
import logging
import math
import os
import shutil
import signal
import sys
import threading
import time
from collections import deque, defaultdict
from datetime import datetime
from pathlib import Path

# Try imports
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
except Exception:
    print("Missing dependency: watchdog. Install with: pip install watchdog")
    raise SystemExit(1)
try:
    import psutil
except Exception:
    psutil = None  # optional
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
except Exception:
    tk = None

# ---------------- Defaults ----------------
DEFAULT_WATCH = [str(Path.home() / "Desktop"), str(Path.home() / "Documents")]
HONEYPOT_DIRNAME = "honeypot_for_detection"
WINDOW_SECONDS = 5
EVENT_RATE_THRESHOLD = 40
EXT_CHANGE_THRESHOLD = 8
ENTROPY_THRESHOLD = 7.0
ENTROPY_MIN_FILES = 3
LOG_FILE = "smart_ransom_detector.log"
QUARANTINE_DIR = str(Path.cwd() / "quarantine")

# ---------------- Logging ----------------
logger = logging.getLogger("SmartRansomDetector")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)

# ---------------- Utilities ----------------
def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path

def move_to_quarantine(filepath, quarantine_dir=QUARANTINE_DIR):
    ensure_dir(quarantine_dir)
    try:
        if not os.path.exists(filepath):
            return None
        basename = os.path.basename(filepath)
        dest = os.path.join(quarantine_dir, f"{int(time.time())}_{basename}")
        shutil.move(filepath, dest)
        logger.info(f"Quarantined: {filepath} -> {dest}")
        return dest
    except Exception as e:
        logger.exception(f"Failed to quarantine {filepath}: {e}")
        return None

def calculate_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0]*256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy

def find_procs_touching_files(filepaths, top_n=5):
    results = []
    if not psutil:
        return results
    counts = defaultdict(int)
    for proc in psutil.process_iter(['pid','name']):
        try:
            of = proc.open_files()
            if not of:
                continue
            open_paths = {o.path for o in of if hasattr(o, 'path')}
            for fp in filepaths:
                try:
                    if fp and os.path.exists(fp) and fp in open_paths:
                        counts[(proc.pid, proc.info.get('name'))] += 1
                except Exception:
                    continue
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        except Exception:
            continue
    for (pid_name, cnt) in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        pid, name = pid_name
        results.append((pid, name, cnt))
    return results

# ---------------- Detector ----------------
class DetectorHandler(FileSystemEventHandler):
    def __init__(self, detector):
        super().__init__()
        self.detector = detector

    def on_any_event(self, event):
        if getattr(event, 'is_directory', False):
            return
        self.detector.register_event(event)

class SmartRansomwareDetector:
    def __init__(self, watch_paths=None, window_seconds=WINDOW_SECONDS,
                 rate_threshold=EVENT_RATE_THRESHOLD, ext_threshold=EXT_CHANGE_THRESHOLD,
                 entropy_threshold=ENTROPY_THRESHOLD, auto_quarantine=False,
                 auto_kill=False, quarantine_dir=QUARANTINE_DIR, ui_logger=None):
        self.watch_paths = watch_paths or DEFAULT_WATCH
        self.window_seconds = window_seconds
        self.rate_threshold = rate_threshold
        self.ext_threshold = ext_threshold
        self.entropy_threshold = entropy_threshold
        self.auto_quarantine = auto_quarantine
        self.auto_kill = auto_kill
        self.quarantine_dir = quarantine_dir
        self.ui_logger = ui_logger

        self.lock = threading.Lock()
        self.events = deque()
        self.ext_changes = deque()
        self.modified = deque()
        self.observer = Observer()
        self.handler = DetectorHandler(self)
        self._running = False

    def log(self, message, level='info'):
        if level == 'info':
            logger.info(message)
        elif level == 'warning':
            logger.warning(message)
        elif level == 'critical':
            logger.critical(message)
        else:
            logger.debug(message)
        if self.ui_logger:
            try:
                self.ui_logger(message)
            except Exception:
                pass

    def ensure_honeypots(self):
        for p in self.watch_paths:
            try:
                target = Path(p) / HONEYPOT_DIRNAME
                ensure_dir(target)
                hp = target / "DO_NOT_TOUCH.txt"
                if not hp.exists():
                    hp.write_text("Honeypot: do not modify. Any modification signals suspicious activity.")
                    self.log(f"Created honeypot: {hp}")
            except Exception as e:
                self.log(f"Honeypot creation failed under {p}: {e}", level='warning')

    def start(self):
        self.log("Starting Smart Ransomware Detector")
        self.ensure_honeypots()
        # schedule watchers
        for p in self.watch_paths:
            if not os.path.exists(p):
                self.log(f"Watch path not found: {p}", level='warning')
                continue
            try:
                self.observer.schedule(self.handler, path=p, recursive=True)
                self.log(f"Watching: {p}")
            except Exception as e:
                self.log(f"Failed to schedule watcher for {p}: {e}", level='warning')
        self.observer.start()
        self._running = True
        threading.Thread(target=self._analysis_loop, daemon=True).start()

    def stop(self):
        self.log("Stopping detector")
        self._running = False
        try:
            self.observer.stop()
            self.observer.join(timeout=2)
        except Exception:
            pass

    def register_event(self, event):
        ts = time.time()
        with self.lock:
            self.events.append((ts, event))
            try:
                if event.event_type == 'moved':
                    src_ext = os.path.splitext(getattr(event, 'src_path', '') or '')[1].lower()
                    dest_ext = os.path.splitext(getattr(event, 'dest_path', '') or '')[1].lower()
                    if src_ext != dest_ext:
                        self.ext_changes.append((ts, src_ext, dest_ext, getattr(event,'src_path', ''), getattr(event,'dest_path','')))
                elif event.event_type in ('modified','created'):
                    self.modified.append((ts, getattr(event,'src_path', getattr(event,'dest_path',''))))
                    pathinfo = getattr(event,'src_path', getattr(event,'dest_path',''))
                    if HONEYPOT_DIRNAME in (pathinfo or '').lower():
                        self.log(f"HONEYPOT TRIGGER: {pathinfo}", level='critical')
                        # immediate alert
                        self._handle_alert(honeypot=True, filepaths=[pathinfo])
            except Exception as e:
                self.log(f"Error processing event: {e}", level='warning')

    def _analysis_loop(self):
        while self._running:
            time.sleep(max(1, self.window_seconds//2))
            threading.Thread(target=self._analyze, daemon=True).start()

    def _analyze(self):
        cutoff = time.time() - self.window_seconds
        with self.lock:
            while self.events and self.events[0][0] < cutoff:
                self.events.popleft()
            while self.ext_changes and self.ext_changes[0][0] < cutoff:
                self.ext_changes.popleft()
            while self.modified and self.modified[0][0] < cutoff:
                self.modified.popleft()
            event_count = len(self.events)
            ext_count = len(self.ext_changes)
            modified_paths = [p for (_,p) in list(self.modified)]
        entropy_avg = 0.0
        entropy_count = 0
        if len(modified_paths) >= ENTROPY_MIN_FILES:
            for p in modified_paths[:50]:
                try:
                    if p and os.path.exists(p):
                        with open(p,'rb') as f:
                            chunk = f.read(4096)
                            if chunk:
                                e = calculate_entropy_bytes(chunk)
                                entropy_avg += e
                                entropy_count += 1
                except Exception:
                    continue
            if entropy_count:
                entropy_avg /= entropy_count
        self.log(f"Analyze -> events={event_count}, ext_changes={ext_count}, avg_entropy={entropy_avg:.2f}", level='debug')
        suspicious = ((event_count >= self.rate_threshold) or (ext_count >= self.ext_threshold) or (entropy_count and (entropy_avg >= self.entropy_threshold)))
        if suspicious:
            recent_paths = modified_paths[-200:]
            self._handle_alert(event_count=event_count, ext_count=ext_count, entropy_avg=entropy_avg, filepaths=recent_paths)

    def _handle_alert(self, honeypot=False, event_count=0, ext_count=0, entropy_avg=0.0, filepaths=None):
        filepaths = filepaths or []
        now = datetime.utcnow().isoformat()
        if honeypot:
            msg = f"[{now}] HONEYPOT TRIGGERED — HIGH CONFIDENCE"
            self.log(msg, level='critical')
        else:
            msg = f"[{now}] Suspicious: events={event_count}, ext_changes={ext_count}, avg_entropy={entropy_avg:.2f}"
            self.log(msg, level='warning')
        procs = find_procs_touching_files(filepaths)
        if procs:
            for pid,name,cnt in procs:
                self.log(f"Likely process -> PID={pid}, name={name}, matched_files={cnt}", level='warning')
                if self.auto_kill and psutil:
                    try:
                        p = psutil.Process(pid); p.terminate(); self.log(f"Terminated PID={pid} ({name})", level='warning')
                    except Exception:
                        self.log(f"Failed to terminate PID={pid}", level='warning')
        else:
            self.log("No process matched open-files (best-effort).", level='info')
        if self.auto_quarantine:
            moved = 0
            for fp in filepaths:
                try:
                    if fp and os.path.exists(fp) and not str(fp).startswith(self.quarantine_dir):
                        if move_to_quarantine(fp, self.quarantine_dir):
                            moved += 1
                except Exception:
                    continue
            self.log(f"Auto-quarantined {moved} files", level='info')
        # incident report
        try:
            ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            rpt = f"incident_{ts}.txt"
            with open(rpt,'w') as f:
                f.write(f"Incident Report - {datetime.utcnow().isoformat()} UTC\n")
                f.write(f"Watch paths: {self.watch_paths}\n")
                f.write(f"Window seconds: {self.window_seconds}\n")
                f.write(f"Event count: {event_count}\n")
                f.write(f"Extension change count: {ext_count}\n")
                f.write(f"Average entropy: {entropy_avg:.2f}\n")
                f.write("Processes:\n")
                if procs:
                    for pid,name,cnt in procs:
                        f.write(f\" - PID={pid}, name={name}, matched_files={cnt}\\n\")
                else:
                    f.write(\" - None (best-effort mapping failed)\\n\")
                f.write(f\"Recent files:\\n\")
                for fp in (filepaths or [])[:200]:
                    f.write(f\" - {fp}\\n\")
                f.write(f\"Log file: {LOG_FILE}\\n\")
            self.log(f\"Wrote incident report: {rpt}\", level='info')
        except Exception as e:
            self.log(f\"Failed to write incident report: {e}\", level='warning')
        with self.lock:
            self.events.clear(); self.ext_changes.clear(); self.modified.clear()

# ---------------- GUI ----------------
class DetectorGUI:
    def __init__(self, detector: SmartRansomwareDetector):
        if tk is None:
            raise RuntimeError(\"Tkinter not available\")
        self.detector = detector
        self.root = tk.Tk(); self.root.title(\"Smart Ransomware Detector\"); self.root.geometry(\"820x520\")
        frame = ttk.Frame(self.root); frame.pack(fill='x', padx=8, pady=6)
        self.start_btn = ttk.Button(frame, text='Start', command=self.start); self.start_btn.pack(side='left', padx=4)
        self.stop_btn = ttk.Button(frame, text='Stop', command=self.stop, state='disabled'); self.stop_btn.pack(side='left', padx=4)
        ttk.Button(frame, text='Open Quarantine', command=self.open_quarantine).pack(side='right')
        self.log_box = scrolledtext.ScrolledText(self.root, wrap='word', height=28); self.log_box.pack(fill='both', expand=True, padx=8, pady=6)
        self.update_loop()

    def ui_logger(self, message):
        ts = datetime.now().strftime('%H:%M:%S')
        try:
            self.log_box.insert('end', f\"[{ts}] {message}\\n\"); self.log_box.see('end')
        except Exception:
            pass

    def update_loop(self):
        # pull from detector via its ui_logger callback mechanism
        self.root.after(200, self.update_loop)

    def start(self):
        self.detector.ui_logger = self.ui_logger
        self.detector.start()
        self.start_btn['state'] = 'disabled'; self.stop_btn['state'] = 'normal'; self.ui_logger('[*] Detector started.')

    def stop(self):
        self.detector.stop()
        self.start_btn['state'] = 'normal'; self.stop_btn['state'] = 'disabled'; self.ui_logger('[*] Detector stopped.')

    def open_quarantine(self):
        path = os.path.abspath(self.detector.quarantine_dir)
        if os.path.exists(path):
            if sys.platform == 'win32': os.startfile(path)
            elif sys.platform == 'darwin': subprocess.run(['open', path])
            else: subprocess.run(['xdg-open', path])
        else:
            messagebox.showinfo('Quarantine', 'Quarantine folder does not exist yet.')

# ---------------- CLI and Runner ----------------
def parse_args():
    p = argparse.ArgumentParser(description='Smart Ransomware Detector (GUI + Headless)')
    p.add_argument('--watch', nargs='*', help='Paths to watch (overrides defaults)')
    p.add_argument('--window', type=int, default=WINDOW_SECONDS)
    p.add_argument('--rate', type=int, default=EVENT_RATE_THRESHOLD)
    p.add_argument('--ext-threshold', type=int, default=EXT_CHANGE_THRESHOLD)
    p.add_argument('--entropy', type=float, default=ENTROPY_THRESHOLD)
    p.add_argument('--auto-quarantine', action='store_true')
    p.add_argument('--auto-kill', action='store_true')
    p.add_argument('--nogui', action='store_true')
    p.add_argument('--simulate', action='store_true')
    p.add_argument('--simulate-dir', default=str(Path.cwd() / 'sim_target'))
    return p.parse_args()

def simulate_activity(target_dir, create_files=150, rename_delay=0.01):
    logger.info(f\"Simulation: creating {create_files} files in {target_dir}\")
    ensure_dir(target_dir)
    created = []
    for i in range(create_files):
        try:
            f = os.path.join(target_dir, f\"sim_{i}.txt\")
            with open(f,'w') as fh: fh.write('simulation')
            created.append(f)
        except Exception:
            continue
    time.sleep(0.3)
    for f in created:
        try:
            os.rename(f, f + '.locked'); time.sleep(rename_delay)
        except Exception:
            continue
    logger.info('Simulation finished')

def main():
    args = parse_args()
    watch = args.watch if args.watch else DEFAULT_WATCH
    detector = SmartRansomwareDetector(watch_paths=watch,
                                      window_seconds=args.window,
                                      rate_threshold=args.rate,
                                      ext_threshold=args.ext_threshold,
                                      entropy_threshold=args.entropy,
                                      auto_quarantine=args.auto_quarantine,
                                      auto_kill=args.auto_kill,
                                      quarantine_dir=args.quarantine_dir if hasattr(args,'quarantine_dir') else QUARANTINE_DIR,
                                      ui_logger=None)
    # signals
    def _sig(sig, frame):
        logger.info('Signal received - stopping'); detector.stop(); sys.exit(0)
    signal.signal(signal.SIGINT, _sig); signal.signal(signal.SIGTERM, _sig)

    if args.simulate:
        detector.start(); time.sleep(1.5); simulate_activity(args.simulate_dir); time.sleep(2); detector.stop(); return

    # decide GUI vs headless
    if not args.nogui and tk is not None and sys.stdout.isatty():
        gui = DetectorGUI(detector); gui.start()
        gui.root.protocol('WM_DELETE_WINDOW', gui.stop); gui.root.mainloop()
    else:
        detector.start(); logger.info('Running headless. Press Ctrl+C to stop.'); 
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            detector.stop()

if __name__ == '__main__':
    main()
