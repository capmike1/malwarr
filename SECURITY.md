# Security

Malwarr is a detection tool, not a guarantee. Please read this before relying on it.

## What it catches

- **Type mismatch**: a file named like media (`.mkv`, `.mp4`, etc.) or a script/executable
  extension, whose actual binary content (checked via `libmagic`) is a Windows PE executable,
  DOS executable, ELF binary, Mach-O binary, or shell script.
- **Dangerous extensions**: files with `.exe`, `.scr`, `.bat`, `.cmd`, `.com`, `.pif`, `.msi`,
  `.vbs`, `.js`, `.jar`, `.scf`, or `.lnk` extensions, regardless of content.
- **Known malware signatures**: via ClamAV, if `CLAMAV_ENABLED=true` (default).

## What it does NOT catch

- A malicious payload packaged inside a genuinely valid video container (e.g., a crafted MKV
  exploiting a player vulnerability). This requires deep content inspection Malwarr does not do.
- Zero-day malware with no ClamAV signature yet.
- Anything that isn't a file on disk under the scanned paths (e.g., malicious scripts embedded
  in NFO/subtitle text that a *different* tool later executes).

Malwarr is a second layer of defense, not a replacement for not running untrusted executables,
keeping your media server software patched, and using a reputable VPN/firewall setup around your
download client.

## Reporting a detection gap or false positive

Open an issue with:
- The file name (or a redacted version if sensitive)
- Output of `file -b <path>` on the file in question
- Whether ClamAV was enabled

False positives will quarantine a legitimate file — Malwarr never deletes automatically, so
recovery is just moving the file back from `/quarantine`.

## Reporting a vulnerability in Malwarr itself

Open a GitHub issue or, for anything sensitive, contact the maintainer directly via the contact
info on their GitHub profile.
