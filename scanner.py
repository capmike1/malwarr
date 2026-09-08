#!/usr/bin/env python3
"""
Malwarr - scans media files for disguised executables and known malware
before they reach Tdarr / the library. Two modes:
  - watch:  short-interval loop over /data/downloads (the gate before import)
  - sweep:  full pass over /data/media (scheduled, incremental via state db)
"""
import os
import sys
import json
import time
import shutil
import subprocess
import urllib.request
import hashlib

DOWNLOADS_DIR = "/data/downloads"
MEDIA_DIR = "/data/media"
QUARANTINE_DIR = "/quarantine"
STATE_DIR = "/state"
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")

MEDIA_EXTENSIONS = {".mkv", ".mp4", ".avi", ".m2ts", ".ts", ".mov", ".wmv", ".m4v"}
# extensions that should NEVER appear as the real file type, regardless of name
DANGEROUS_MAGIC_SUBSTRINGS = [
    "PE32", "PE32+", "MS-DOS", "DOS executable", "MZ for MS-DOS",
    "ELF ", "Mach-O", "shell script", "Bourne-Again shell script",
]

def load_state(name):
    path = os.path.join(STATE_DIR, f"{name}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}

def save_state(name, state):
    path = os.path.join(STATE_DIR, f"{name}.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, path)

def notify(message, is_alert=False):
    if not WEBHOOK_URL:
        print(f"[notify - no webhook configured] {message}")
        return
    prefix = "\U0001F6A8 **Malwarr Alert**\n" if is_alert else "\U0001F9FE **Malwarr**\n"
    payload = json.dumps({"content": prefix + message}).encode()
    req = urllib.request.Request(
        WEBHOOK_URL, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Malwarr/1.0 (Unraid media scanner)",
        },
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[notify failed] {e}")

def file_magic(path):
    try:
        r = subprocess.run(["file", "-b", path], capture_output=True, text=True, timeout=30)
        return r.stdout.strip()
    except Exception as e:
        return f"file-check-error: {e}"

def clamav_scan(path):
    """Returns (infected: bool, signature: str or None)"""
    try:
        r = subprocess.run(
            ["clamscan", "--no-summary", path],
            capture_output=True, text=True, timeout=600,
        )
        # clamscan exit code 1 = virus found, output line: "path: SIGNATURE FOUND"
        if r.returncode == 1:
            line = r.stdout.strip()
            sig = line.split(":", 1)[1].strip() if ":" in line else line
            return True, sig
        return False, None
    except Exception as e:
        print(f"[clamav error] {path}: {e}")
        return False, None

def quarantine_file(path, reason):
    rel = os.path.relpath(path, "/data")
    dest = os.path.join(QUARANTINE_DIR, rel.replace(os.sep, "__"))
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    try:
        shutil.move(path, dest)
        return dest
    except Exception as e:
        notify(f"Failed to quarantine `{path}`: {e}", is_alert=True)
        return None

def scan_one(path):
    """Returns finding dict or None"""
    ext = os.path.splitext(path)[1].lower()
    magic = file_magic(path)

    # 1. magic-byte / extension mismatch check (fast, catches disguised executables)
    if ext in MEDIA_EXTENSIONS or ext in {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".vbs", ".js", ".jar", ".scf", ".lnk"}:
        for bad in DANGEROUS_MAGIC_SUBSTRINGS:
            if bad in magic:
                return {"path": path, "reason": "type-mismatch", "detail": f"named like media/script but is: {magic}"}

    # 2. real extension is already a known-dangerous type regardless of magic
    if ext in {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".vbs", ".js", ".jar", ".scf", ".lnk"}:
        return {"path": path, "reason": "dangerous-extension", "detail": magic}

    # 3. ClamAV signature scan
    if os.environ.get("CLAMAV_ENABLED", "true").lower() == "true":
        infected, sig = clamav_scan(path)
        if infected:
            return {"path": path, "reason": "clamav-signature", "detail": sig}

    return None

def handle_finding(finding):
    dest = quarantine_file(finding["path"], finding["reason"])
    msg = (
        f"**{finding['reason']}**\n"
        f"File: `{finding['path']}`\n"
        f"Detail: {finding['detail']}\n"
        f"{'Quarantined to: `' + dest + '`' if dest else 'QUARANTINE FAILED - file left in place, check manually'}"
    )
    notify(msg, is_alert=True)
    print(f"FLAGGED: {finding['path']} -> {finding['reason']} ({finding['detail']})")

def file_fingerprint(path):
    st = os.stat(path)
    return f"{st.st_size}:{int(st.st_mtime)}"

def walk_and_scan(root, state_name, skip_unchanged=True):
    state = load_state(state_name) if skip_unchanged else {}
    scanned = 0
    flagged = 0
    for dirpath, _, filenames in os.walk(root):
        # never rescan our own quarantine or state dirs if nested
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            try:
                fp = file_fingerprint(path)
            except FileNotFoundError:
                continue
            if skip_unchanged and state.get(path) == fp:
                continue
            finding = scan_one(path)
            scanned += 1
            if finding:
                flagged += 1
                handle_finding(finding)
                continue  # don't record state for a file we just moved
            state[path] = fp
            if scanned % 200 == 0:
                save_state(state_name, state)
    save_state(state_name, state)
    return scanned, flagged

def run_watch_loop():
    interval = int(os.environ.get("WATCH_INTERVAL_SECONDS", "120"))
    notify(f"Malwarr download watcher started (checking every {interval}s).")
    while True:
        try:
            scanned, flagged = walk_and_scan(DOWNLOADS_DIR, "downloads", skip_unchanged=True)
            if scanned:
                print(f"[watch] scanned {scanned} new/changed files, {flagged} flagged")
        except Exception as e:
            print(f"[watch loop error] {e}")
        time.sleep(interval)

def run_media_sweep():
    start = time.time()
    notify(f"Media library sweep starting (`{MEDIA_DIR}`)...")
    scanned, flagged = walk_and_scan(MEDIA_DIR, "media", skip_unchanged=True)
    elapsed = time.time() - start
    notify(
        f"Media sweep complete. Scanned {scanned} new/changed files in {elapsed/60:.1f} min. "
        f"{'**' + str(flagged) + ' flagged and quarantined**' if flagged else 'Nothing found.'}"
    )

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "watch"
    os.makedirs(STATE_DIR, exist_ok=True)
    if mode == "watch":
        run_watch_loop()
    elif mode == "sweep":
        run_media_sweep()
    else:
        print(f"unknown mode: {mode}")
        sys.exit(1)
