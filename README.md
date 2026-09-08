# Malwarr

A lightweight *arr-family-style scanner that sits between your download client and your media
library, catching malware disguised as movies/TV episodes before they get imported or transcoded.

Built after finding that ~90% of an active qBittorrent download queue was Windows executables
padded to look like 1080p releases (`.exe`/`.scr` files sized to mimic real video downloads,
with scene-release-style names). Malwarr catches that pattern, plus real malware via ClamAV.

## How it works

Two scan modes, one container:

- **Downloads watch** — polls a configurable path (e.g. your qBittorrent download folder) every
  couple of minutes. This is the gate before Radarr/Sonarr/Whisparr import anything or Tdarr
  touches it.
- **Media sweep** — a full pass over your library on a schedule you control (default 1 AM daily),
  incremental after the first run so it's not rescanning terabytes every night.

Detection is two-layered:
1. **Magic-byte / extension check** — uses `libmagic` to check what a file *actually is*,
   independent of its name. Catches a `.mkv`-looking file that's really a PE32 executable, and
   flags any file with a dangerous extension (`.exe`, `.scr`, `.bat`, etc.) outright.
2. **ClamAV** — real signature-based malware scanning, optional but on by default.

Anything flagged is **quarantined, never auto-deleted** — moved to a separate folder for you to
review. A Discord webhook notification fires on every finding and after every sweep.

See [SECURITY.md](SECURITY.md) for exactly what this does and doesn't catch.

## Quick start

```bash
docker run -d --name=malwarr \
  --cpus=2 \
  -e PUID=99 \
  -e PGID=100 \
  -e TZ=America/New_York \
  -e MEDIA_SCAN_START_HOUR=01:00 \
  -e CLAMAV_ENABLED=true \
  -e WATCH_INTERVAL_SECONDS=120 \
  -e MIN_FILE_AGE_SECONDS=90 \
  -e DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...' \
  -v /path/to/downloads:/data/downloads \
  -v /path/to/media:/data/media \
  -v /path/to/quarantine:/quarantine \
  -v /path/to/appdata/malwarr/state:/state \
  -v /path/to/appdata/malwarr/clamav-db:/var/lib/clamav \
  --restart=unless-stopped \
  ghcr.io/capmike1/malwarr:latest
```

On Unraid, use the Community Applications template (see [Unraid install](#unraid-install) below)
instead of a raw `docker run`.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PUID` / `PGID` | `99` / `100` | User/group the scanner and ClamAV actually run as (defaults match Unraid's `nobody:users`). The container starts as root only long enough to set this up, then drops privileges — nothing scans or writes files as root. |
| `DISCORD_WEBHOOK_URL` | *(none)* | Discord webhook for notifications. If unset, findings are only logged to container stdout. |
| `MEDIA_SCAN_START_HOUR` | `01:00` | 24h `HH:MM` — when the daily `/data/media` sweep starts. It runs to completion, not on a fixed window. |
| `WATCH_INTERVAL_SECONDS` | `120` | How often `/data/downloads` is checked for new/changed files. |
| `MIN_FILE_AGE_SECONDS` | `90` | Files modified more recently than this are skipped for one cycle — avoids scanning/moving a file that's still being actively written (e.g. mid-download). |
| `CLAMAV_ENABLED` | `true` | Set to `false` to skip ClamAV and rely only on the magic-byte/extension check (much lighter, still catches the exact pattern this tool was built for). |
| `TZ` | *(container default)* | Standard timezone string, affects when the scheduled sweep fires. |

## Notes on safety

- Findings are **quarantined, never deleted automatically** — a false positive costs you a manual
  move back, not the file.
- Quarantine uses collision-safe naming — two different flagged files that would map to the same
  quarantine filename never overwrite each other.
- If a flagged file had an open file handle at scan time (e.g. Plex was streaming it, Tdarr was
  transcoding it), the Discord alert notes that. The move itself doesn't disrupt an
  already-open reader on Linux, but it does mean the file vanishes from its expected library path
  going forward — which is the point for a genuine finding.
- If ClamAV's virus definitions go stale (freshclam silently failing for a couple of days), the
  next media sweep will alert you instead of quietly scanning against outdated signatures.

## Volume mounts

| Container path | Purpose |
|---|---|
| `/data/downloads` | Your download client's completed-downloads folder. Scanned continuously. |
| `/data/media` | Your media library root. Scanned on the nightly schedule. |
| `/quarantine` | Where flagged files get moved. Give it real disk space — quarantine is not automatically cleaned up. |
| `/state` | Persists the incremental-scan state so restarts don't trigger a full rescan. |
| `/var/lib/clamav` | Persists ClamAV virus definitions across container recreation (avoids a ~100MB re-download every restart). |

## Updating

`docker run` does **not** re-check a tag it already has cached locally — if you're managing this
outside Unraid's Docker UI (which handles this for you), run `docker pull ghcr.io/capmike1/malwarr:latest`
before recreating the container, or you'll silently keep running the old image under a `:latest`
tag that looks current but isn't.

## Resource notes

- ClamAV scanning is CPU-intensive on a full library sweep. `--cpus=2` (or similar) is
  recommended so it doesn't compete with transcoding.
- First run downloads ClamAV definitions (~100MB) before the watch loop starts — expect a
  couple of minutes before the container reports ready.

## Unraid install

1. In Community Applications settings, add this repo as a **Template Repository**:
   `https://github.com/capmike1/malwarr`
2. Search for "Malwarr" in Community Applications and install normally.
3. Set your Discord webhook and confirm the mount paths match your existing `/data` structure.

(Not yet in the default curated App Feed — the template repository method above works
immediately without waiting on that.)

## Why "Malwarr"

It sits in the same pipeline as Radarr/Sonarr/Prowlarr/Bazarr — same naming convention, does
for malware detection what they do for acquisition and organization.

## License

MIT — see [LICENSE](LICENSE).
