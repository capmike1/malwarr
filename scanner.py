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
# skip files modified more recently than this - avoids scanning/moving a file
# that's still being actively written (e.g. mid-download), which could
# produce a false read or, worse, yank a file out from under the writer
MIN_FILE_AGE_SECONDS = int(os.environ.get("MIN_FILE_AGE_SECONDS", "90"))

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

def file_in_use(path):
    """Best-effort check whether another process currently has the file open.
    Informational only - we still quarantine either way (on Linux, moving a
    file doesn't disrupt an already-open reader/writer's file descriptor),
    but it's worth surfacing in the alert so the user knows a stream/job
    might have been touching it at the moment it was flagged."""
    try:
        r = subprocess.run(["lsof", "--", path], capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and path in r.stdout
    except Exception:
        return False

def quarantine_file(path, reason):
    rel = os.path.relpath(path, "/data")
    base_dest = os.path.join(QUARANTINE_DIR, rel.replace(os.sep, "__"))
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    dest = base_dest
    if os.path.exists(dest):
        # collision - never silently overwrite a previous quarantine entry
        stamp = int(time.time())
        dest = f"{base_dest}.{stamp}"
        n = 1
        while os.path.exists(dest):
            dest = f"{base_dest}.{stamp}-{n}"
            n += 1
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
    was_open = file_in_use(finding["path"])
    dest = quarantine_file(finding["path"], finding["reason"])
    msg = (
        f"**{finding['reason']}**\n"
        f"File: `{finding['path']}`\n"
        f"Detail: {finding['detail']}\n"
        f"{'Quarantined to: `' + dest + '`' if dest else 'QUARANTINE FAILED - file left in place, check manually'}"
        f"{chr(10) + '_Note: this file had an open handle at scan time (e.g. actively playing/transcoding) - already-open readers are unaffected by the move._' if was_open else ''}"
    )
    notify(msg, is_alert=True)
    print(f"FLAGGED: {finding['path']} -> {finding['reason']} ({finding['detail']})")

def clamav_definitions_age_days():
    """Returns age in days of the newest ClamAV definition file, or None if none found."""
    candidates = ["/var/lib/clamav/daily.cvd", "/var/lib/clamav/daily.cld"]
    mtimes = [os.path.getmtime(p) for p in candidates if os.path.exists(p)]
    if not mtimes:
        return None
    return (time.time() - max(mtimes)) / 86400

def walk_and_scan(root, state_name, skip_unchanged=True):
    state = load_state(state_name) if skip_unchanged else {}
    scanned = 0
    flagged = 0
    for dirpath, _, filenames in os.walk(root):
        # never rescan our own quarantine or state dirs if nested
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            try:
                st = os.stat(path)
            except FileNotFoundError:
                continue
            # skip files still being actively written (e.g. mid-download) -
            # scanning/moving a growing file risks a false read or corrupting
            # the writer's in-progress operation. It'll be picked up once stable.
            if time.time() - st.st_mtime < MIN_FILE_AGE_SECONDS:
                continue
            fp = f"{st.st_size}:{int(st.st_mtime)}"
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
    if os.environ.get("CLAMAV_ENABLED", "true").lower() == "true":
        age = clamav_definitions_age_days()
        if age is None:
            notify("**ClamAV definitions not found** - signature scanning is effectively disabled. Check freshclam logs.", is_alert=True)
        elif age > 2:
            notify(f"**ClamAV definitions are {age:.1f} days old** - freshclam may be failing silently. Signature detection is running on stale data.", is_alert=True)
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
