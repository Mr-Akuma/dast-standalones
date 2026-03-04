#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   EDUCATIONAL KEYSTROKE MONITOR — Security Awareness Demo        ║
║   For authorized lab / classroom use ONLY                        ║
║   Purpose: Show students HOW keyloggers work so they can         ║
║            DETECT and DEFEND against them                        ║
╚══════════════════════════════════════════════════════════════════╝

USAGE:
    python3 keystroke_demo.py              # monitor to console
    python3 keystroke_demo.py --log        # also log to file
    python3 keystroke_demo.py --detect     # show detection techniques only

REQUIREMENTS:
    pip install pynput

LEGAL NOTICE:
    Only run on machines you OWN or have EXPLICIT WRITTEN CONSENT to monitor.
    Unauthorized keylogging is illegal in most jurisdictions.
"""

import sys
import time
import datetime
import argparse
import platform
from pathlib import Path

# ── Graceful import ───────────────────────────────────────────────────────────
try:
    from pynput import keyboard
except ImportError:
    print("❌  pynput not installed — run:  pip install pynput")
    sys.exit(1)


# ── Config ────────────────────────────────────────────────────────────────────
LOG_FILE    = Path("keystroke_demo.log")
FLUSH_EVERY = 10          # write to log every N keystrokes
BANNER      = """
┌─────────────────────────────────────────────────────────────────┐
│  🔴  KEYSTROKE MONITOR ACTIVE  —  Educational Demo              │
│  Press  Ctrl+C  or  Esc  to stop                                │
│  THIS BANNER IS WHAT A REAL KEYLOGGER WOULD HIDE                │
└─────────────────────────────────────────────────────────────────┘
"""


# ── Core monitor ──────────────────────────────────────────────────────────────
class KeystrokeMonitor:
    """Transparent educational keystroke monitor."""

    def __init__(self, log_to_file: bool = False):
        self.log_to_file  = log_to_file
        self.log_file     = LOG_FILE if log_to_file else None
        self.buffer       = []
        self.count        = 0
        self.start_time   = time.time()
        self.running      = False
        self._listener    = None

        if log_to_file:
            with open(self.log_file, "w") as f:
                f.write(f"# Keystroke Demo Log — {datetime.datetime.now()}\n")
                f.write("# timestamp | key\n\n")
            print(f"📄 Logging to: {self.log_file.resolve()}")

    # ── Key event handlers ────────────────────────────────────────────────
    def on_press(self, key):
        try:
            char = key.char                     # printable character
        except AttributeError:
            char = f"[{key.name}]"             # special key: [enter], [ctrl], etc.

        ts  = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        msg = f"  {ts}  KEY: {char!r}"
        print(msg)

        self.buffer.append(f"{ts} | {char}\n")
        self.count += 1

        if self.log_to_file and len(self.buffer) >= FLUSH_EVERY:
            self._flush()

        # Stop on Escape
        if key == keyboard.Key.esc:
            print("\n⛔  Esc pressed — stopping monitor")
            return False   # pynput convention: return False to stop listener

    def on_release(self, key):
        pass   # not used in this demo, but real keyloggers capture key-up too

    def _flush(self):
        if self.log_file and self.buffer:
            with open(self.log_file, "a") as f:
                f.writelines(self.buffer)
            self.buffer.clear()

    # ── Run ───────────────────────────────────────────────────────────────
    def start(self):
        print(BANNER)
        self.running = True
        try:
            with keyboard.Listener(
                on_press=self.on_press,
                on_release=self.on_release,
            ) as listener:
                self._listener = listener
                listener.join()
        except KeyboardInterrupt:
            print("\n⛔  Ctrl+C — stopping monitor")
        finally:
            self._flush()
            self._summary()

    def _summary(self):
        elapsed = time.time() - self.start_time
        print(f"\n{'─'*50}")
        print(f"  Total keystrokes captured : {self.count}")
        print(f"  Monitoring duration       : {elapsed:.1f}s")
        if self.log_to_file:
            print(f"  Log saved to              : {self.log_file.resolve()}")
        print(f"{'─'*50}\n")


# ── Detection guide ───────────────────────────────────────────────────────────
DETECTION_GUIDE = """
╔══════════════════════════════════════════════════════════════════╗
║   HOW TO DETECT A KEYLOGGER — What to teach your students        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  1. PROCESS INSPECTION                                           ║
║     macOS:   ps aux | grep -i pynput                             ║
║              Activity Monitor → CPU tab, sort by %CPU           ║
║     Windows: Task Manager → Details tab                          ║
║              Autoruns (Sysinternals) → check startup entries     ║
║     Linux:   ps aux | grep python                                ║
║                                                                  ║
║  2. NETWORK TRAFFIC (exfil detection)                            ║
║     • Keyloggers often phone home — watch for unexpected         ║
║       outbound connections on port 443/80/25                     ║
║     macOS:   lsof -i | grep ESTABLISHED                          ║
║     Linux:   ss -tnp                                             ║
║     Windows: netstat -anb                                        ║
║                                                                  ║
║  3. FILE SYSTEM ANOMALIES                                        ║
║     • Watch for hidden files (.log, .tmp) in home/temp dirs      ║
║     macOS:   find ~ -name "*.log" -newer /tmp -ls 2>/dev/null   ║
║     Windows: dir /ah %APPDATA% (hidden files)                    ║
║                                                                  ║
║  4. STARTUP / PERSISTENCE                                        ║
║     macOS:   launchctl list | grep -v com.apple                  ║
║              ls ~/Library/LaunchAgents/                          ║
║     Windows: HKCU\Software\Microsoft\Windows\CurrentVersion\Run  ║
║     Linux:   crontab -l && ls /etc/cron.d/                       ║
║                                                                  ║
║  5. ANTIVIRUS / EDR                                              ║
║     • Modern EDRs flag pynput keyboard hooks                     ║
║     • Windows Defender flags keyboard hook APIs                  ║
║     • CrowdStrike / SentinelOne catch hook injection             ║
║                                                                  ║
║  6. HOW THIS DEMO DIFFERS FROM A REAL KEYLOGGER                  ║
║     ✓ Prints banner (real ones are silent)                       ║
║     ✓ No exfiltration (real ones email/POST logs)                ║
║     ✓ No persistence (real ones add to startup)                  ║
║     ✓ No obfuscation (real ones encode/encrypt)                  ║
║     ✓ No process hiding (real ones masquerade as svchost etc)    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Educational keystroke monitor — classroom demo only"
    )
    parser.add_argument("--log",    action="store_true",
                        help="Also log keystrokes to keystroke_demo.log")
    parser.add_argument("--detect", action="store_true",
                        help="Print detection techniques and exit")
    args = parser.parse_args()

    if args.detect:
        print(DETECTION_GUIDE)
        return

    print(f"\n  OS       : {platform.system()} {platform.release()}")
    print(f"  Python   : {sys.version.split()[0]}")
    print(f"  Mode     : {'log to file + console' if args.log else 'console only'}")
    print(f"  ⚠️  CONSENT REMINDER: Only run on your own machine or with written consent\n")

    monitor = KeystrokeMonitor(log_to_file=args.log)
    monitor.start()

    # Always show detection at the end — pedagogically important
    print(DETECTION_GUIDE)


if __name__ == "__main__":
    main()
