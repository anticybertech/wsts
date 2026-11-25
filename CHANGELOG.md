# Changelog

## 1.0.1 — 2026-11-25

### Detection fixes
- **Prefetch matching never fired.** Prefetch files are named `NAME.EXE-HASH.pf`, but the
  code compared `name.exe` against names without the extension, so no tool was ever
  flagged. Names are now parsed correctly (including names that contain hyphens).
- **Prefetch severity tiers.** Known attack and credential-theft tools are **HIGH**;
  dual-use admin tools that attackers abuse (PsExec, certutil, ntdsutil, rclone…) are
  **MEDIUM**; built-in Windows tools (cmd, PowerShell, whoami…) are **INFO** and no longer
  counted as suspicious, since they run on every PC.
- **Event logs no longer flood the report.** Every never-used `.evtx` file is exactly
  69,632 bytes, under the old 70,000-byte "possibly cleared" threshold, so most of the
  hundreds of logs in `winevt\Logs` were reported as HIGH on clean machines. WSTS now:
  - queries the actual log-clearing events (Security 1102, System 104) for the last 30 days;
  - flags an empty Security or System log (those are written constantly on real PCs);
  - lists only the security-relevant logs.
- **Credential hives.** The live SAM/SECURITY/SYSTEM/SOFTWARE hives change constantly,
  so "modified in the last 24h" fired on every scan. Their status is now informational,
  and WSTS instead looks for **exported hive copies or ntds.dit** in Temp, Public,
  ProgramData, PerfLogs and users' Desktop/Downloads/Documents/Temp folders — a strong
  sign of offline password-hash theft.
- **Amcache / NTUSER.DAT** timestamps are informational (they change during normal use).
- Detection rules moved to `wsts_rules.json` (versioned, reviewable, and no longer
  embedded as strings in the executable).

### Dashboard security
- Per-launch session token (URL → HttpOnly, SameSite=Strict cookie); requests without it
  get 403.
- Host header must be `127.0.0.1:<port>` or `localhost:<port>`, which blocks DNS-rebinding
  attacks from malicious web pages.
- The scan and quit APIs require a custom header, so no cross-site request can trigger them.
- Strict Content-Security-Policy with a per-page nonce; no inline event handlers;
  `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `no-store`.
- Every value shown in the dashboard is HTML-escaped.
- Single-instance detection uses a per-user session file
  (`%LOCALAPPDATA%\WSTS\instance.json`); if port 5900 is taken by another program, WSTS
  picks a free port instead of failing.

### Usability
- Requests Administrator rights at launch (UAC prompt), and shows a clear notice when
  running without them.
- New **Quit** button (the windowed build previously had no way to exit besides Task Manager).
- Version and rules version shown in the footer and returned in scan results.

### Build and release
- PyInstaller **folder build** wrapped in a real **Inno Setup installer**
  (`WSTS-Setup-<version>.exe` installs to Program Files with Start-menu entries and an
  uninstaller). The one-file build extracted itself to `%TEMP%` on every run, a
  pattern machine-learning antivirus engines associate with malware droppers.
- `build_wsts.ps1` signs both the app and the installer with **Microsoft Artifact
  Signing**, verifies the signatures chain to a trusted root, and refuses to publish a
  self-signed or unsigned build.
- Optional `-BuildBootloader` compiles PyInstaller's bootloader locally.
- Added `requirements.txt` and a test suite (`python -m pytest -q`).

## 1.0.0 — 2026-06-20
- Initial release.
