r"""
win_scanner_app.py — Windows Security Threat Scanner (Flask web UI)
Scans local Windows artifacts for malware indicators, persistence
mechanisms, and evidence of log/credential-store tampering.

Read-only by design: WSTS never writes to, deletes, or uploads anything it
inspects. The only file it creates is its own session file under
%LOCALAPPDATA%\WSTS (and a log under %TEMP% when built without a console).

Run:  python win_scanner_app.py
The dashboard opens automatically at http://127.0.0.1:<port>/?t=<session token>
"""

import json
import os
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, g, jsonify, make_response, render_template_string, request

__version__ = "1.0.1"

# ---------------------------------------------------------------------------
# Flask setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Per-launch session token. The dashboard only answers requests that carry
# it, so other local programs and web pages (DNS rebinding) cannot read scan
# results even though the server listens on 127.0.0.1.
SESSION_TOKEN = secrets.token_urlsafe(32)
COOKIE_NAME = "wsts_session"
DEFAULT_PORT = 5900
BOUND_PORT = DEFAULT_PORT  # updated at startup

# ---------------------------------------------------------------------------
# Detection rules (loaded from wsts_rules.json next to the app / in the bundle)
# ---------------------------------------------------------------------------

def _resource_dir() -> str:
    """Folder holding bundled data files (dev checkout or PyInstaller bundle)."""
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def load_rules(path: str | None = None) -> dict:
    path = path or os.path.join(_resource_dir(), "wsts_rules.json")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


RULES = load_rules()

_PF = RULES["prefetch"]
PREFETCH_TIERS = [  # (tier key, flag, severity, names) — first match wins
    ("offensive_tools", "KNOWN_OFFENSIVE_TOOL", "HIGH",
     {n.lower() for n in _PF["offensive_tools"]["names"]}),
    ("dual_use_admin", "DUAL_USE_TOOL", "MEDIUM",
     {n.lower() for n in _PF["dual_use_admin"]["names"]}),
    ("builtin_context", "BUILTIN_TOOL", "INFO",
     {n.lower() for n in _PF["builtin_context"]["names"]}),
]

_ST = RULES["startup"]
HIGH_RISK_STARTUP_EXTS = set(_ST["high_risk_exts"])
EXEC_STARTUP_EXTS = set(_ST["exec_exts"])
SUSPICIOUS_LNK_TARGETS = set(_ST["suspicious_lnk_targets"])
SUSPICIOUS_ARG_TOKENS = tuple(_ST["suspicious_arg_tokens"])
SUSPICIOUS_TARGET_DIRS = tuple(_ST["suspicious_target_dirs"])

_HC = RULES["hive_copies"]
HIVE_COPY_NAMES = {n.lower() for n in _HC["file_names"]}
HIVE_COPY_DIRS = list(_HC["search_dirs"])
HIVE_COPY_USER_DIRS = list(_HC["per_user_dirs"])

# Threshold: artifact modified within this many hours = "recent"
RECENT_HOURS = 24
# Look-back window for log-clearing events
LOG_CLEAR_LOOKBACK_DAYS = 30
# A freshly created / never-written .evtx file is exactly this size.
EMPTY_EVTX_BYTES = 69_632

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _age_hours(ts: float) -> float:
    return (_now().timestamp() - ts) / 3600


def _safe_stat(path: str) -> os.stat_result | None:
    try:
        return os.stat(path)
    except (PermissionError, FileNotFoundError, OSError):
        return None


def is_admin() -> bool:
    """True when running elevated (Windows) or as root elsewhere."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return hasattr(os, "geteuid") and os.geteuid() == 0


def prefetch_exe_name(pf_name: str) -> str:
    """'MIMIKATZ.EXE-1A2B3C4D.pf' -> 'MIMIKATZ.EXE' (hyphens in names preserved)."""
    stem = pf_name[:-3] if pf_name.lower().endswith(".pf") else pf_name
    return stem.rsplit("-", 1)[0] if "-" in stem else stem


def classify_prefetch(exe_name: str):
    """Return (flag, severity) for an executable name, or (None, None)."""
    base = os.path.splitext(exe_name.lower())[0]
    for _key, flag, severity, names in PREFETCH_TIERS:
        if base in names:
            return flag, severity
    return None, None

# ---------------------------------------------------------------------------
# Scanner modules
# ---------------------------------------------------------------------------

def scan_prefetch(prefetch_dir: str = r"C:\Windows\Prefetch") -> dict:
    """List prefetch files and flag known offensive / dual-use tools.

    Built-in Windows tools (cmd, powershell, whoami...) are shown for context
    but never counted as suspicious on their own: they run on every PC.
    """
    findings = []

    try:
        with os.scandir(prefetch_dir) as it:
            entries = [Path(e.path) for e in it if e.name.lower().endswith(".pf")]
    except PermissionError:
        return {"accessible": False, "path": prefetch_dir, "findings": [],
                "summary": "Permission denied — run WSTS as Administrator to read Prefetch"}
    except OSError:
        return {"accessible": False, "path": prefetch_dir, "findings": [],
                "summary": "Prefetch folder not found (Prefetch may be disabled on this PC)"}

    for pf in entries:
        st = _safe_stat(str(pf))
        if not st:
            continue
        mtime = st.st_mtime
        exe_name = prefetch_exe_name(pf.name)
        age_h = _age_hours(mtime)

        flags = []
        tier_flag, severity = classify_prefetch(exe_name)
        if tier_flag:
            flags.append(tier_flag)
        if age_h < 1:
            flags.append("RAN_LAST_1H")
        elif age_h < 24:
            flags.append("RAN_LAST_24H")

        if severity is None:
            severity = "LOW"
        # A dual-use tool that ran in the last 24h is worth a closer look.
        if tier_flag == "DUAL_USE_TOOL" and age_h < 24:
            flags.append("RECENT_DUAL_USE")

        findings.append({
            "file": pf.name,
            "exe": exe_name,
            "last_run": _fmt_ts(mtime),
            "age_hours": round(age_h, 1),
            "size_bytes": st.st_size,
            "flags": flags,
            "severity": severity,
        })

    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda x: (rank.get(x["severity"], 4), x["age_hours"]))

    return {
        "accessible": True,
        "path": prefetch_dir,
        "total": len(findings),
        "suspicious_count": sum(1 for f in findings if f["severity"] == "HIGH"),
        "dual_use_count": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "recent_count": sum(1 for f in findings if f["age_hours"] < 24),
        "findings": findings,
    }


def _lnk_decode_ansi(raw: bytes) -> str:
    """Decode an ANSI string from a .lnk using the best available codec."""
    for enc in ("mbcs", "cp1252", "latin-1"):
        try:
            return raw.decode(enc, "replace")
        except (LookupError, UnicodeError):
            continue
    return raw.decode("latin-1", "replace")


def _read_lnk_string(buf: bytes, pos: int, is_unicode: bool):
    """Read one SHLLINK StringData block (2-byte char count + chars)."""
    if pos + 2 > len(buf):
        return "", pos
    count = int.from_bytes(buf[pos:pos + 2], "little")
    pos += 2
    if is_unicode:
        nbytes = count * 2
        text = buf[pos:pos + nbytes].decode("utf-16-le", "replace")
    else:
        nbytes = count
        text = _lnk_decode_ansi(buf[pos:pos + nbytes])
    return text, pos + nbytes


def _resolve_lnk_target(path: str):
    """Best-effort pure-Python parse of a Windows .lnk (MS-SHLLINK).

    Returns (target_path or None, arguments or None). No pywin32 dependency.
    """
    try:
        with open(path, "rb") as fh:
            buf = fh.read(64 * 1024)
        if len(buf) < 76 or buf[0] != 0x4C:
            return None, None

        flags = int.from_bytes(buf[20:24], "little")
        HAS_IDLIST = flags & 0x1
        HAS_LINKINFO = flags & 0x2
        HAS_NAME = flags & 0x4
        HAS_RELPATH = flags & 0x8
        HAS_WORKDIR = flags & 0x10
        HAS_ARGS = flags & 0x20
        IS_UNICODE = flags & 0x80

        pos = 76  # fixed header size

        if HAS_IDLIST:
            if pos + 2 > len(buf):
                return None, None
            idlist_size = int.from_bytes(buf[pos:pos + 2], "little")
            pos += 2 + idlist_size

        target = None
        if HAS_LINKINFO and pos + 4 <= len(buf):
            li_start = pos
            li_size = int.from_bytes(buf[pos:pos + 4], "little")
            li = buf[li_start:li_start + li_size]
            if len(li) >= 28:
                li_flags = int.from_bytes(li[8:12], "little")
                local_base_off = int.from_bytes(li[16:20], "little")
                common_suffix_off = int.from_bytes(li[24:28], "little")
                base = suffix = ""
                if (li_flags & 0x1) and 0 < local_base_off < len(li):
                    end = li.find(b"\x00", local_base_off)
                    base = _lnk_decode_ansi(li[local_base_off:end])
                if 0 < common_suffix_off < len(li):
                    end = li.find(b"\x00", common_suffix_off)
                    suffix = _lnk_decode_ansi(li[common_suffix_off:end])
                if base:
                    target = base + suffix
            pos = li_start + li_size

        rel_path = None
        args = None
        if HAS_NAME:
            _, pos = _read_lnk_string(buf, pos, IS_UNICODE)
        if HAS_RELPATH:
            rel_path, pos = _read_lnk_string(buf, pos, IS_UNICODE)
        if HAS_WORKDIR:
            _, pos = _read_lnk_string(buf, pos, IS_UNICODE)
        if HAS_ARGS:
            args, pos = _read_lnk_string(buf, pos, IS_UNICODE)

        if not target and rel_path:
            try:
                target = os.path.normpath(
                    os.path.join(os.path.dirname(path), rel_path))
            except OSError:
                target = rel_path

        return (target or None), (args or None)
    except (OSError, ValueError, IndexError):
        return None, None


def scan_startup_persistence() -> dict:
    """Check startup folders for persistence artifacts."""
    startup_paths = []

    # Per-user startup
    users_root = r"C:\Users"
    try:
        user_dirs = [d for d in Path(users_root).iterdir() if d.is_dir()]
    except (PermissionError, OSError):
        user_dirs = []

    for ud in user_dirs:
        sp = ud / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        startup_paths.append(("user", ud.name, str(sp)))

    # Global startup
    global_startup = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    startup_paths.append(("global", "All Users", global_startup))

    # Also check registry-equivalent Run keys via text (we read from filesystem only)
    findings = []

    for scope, owner, path in startup_paths:
        try:
            items = list(Path(path).iterdir())
        except (PermissionError, FileNotFoundError, OSError) as e:
            findings.append({
                "scope": scope,
                "owner": owner,
                "path": path,
                "accessible": False,
                "error": str(e),
                "items": [],
            })
            continue

        items_info = []
        for item in items:
            if item.name.startswith("."):
                continue
            st = _safe_stat(str(item))
            ext = item.suffix.lower()
            full_path = str(item)
            flags = []
            target = None
            args = None

            recently = bool(st and _age_hours(st.st_mtime) < RECENT_HOURS)

            if ext == ".lnk":
                target, args = _resolve_lnk_target(full_path)
                tgt_l = (target or "").lower()
                args_l = (args or "").lower()
                tgt_name = os.path.basename(tgt_l)
                bad_target = tgt_name in SUSPICIOUS_LNK_TARGETS
                bad_args = any(tok in args_l for tok in SUSPICIOUS_ARG_TOKENS)
                bad_dir = any(d in tgt_l for d in SUSPICIOUS_TARGET_DIRS)
                if bad_target or bad_args or bad_dir:
                    flags.append("SUSPICIOUS_LNK_TARGET")
                    severity = "HIGH"
                    note = ("This shortcut launches a command interpreter or runs "
                            "from an unusual location. Review the target/command "
                            "shown here before trusting it; if you did not create "
                            "it, delete the .lnk from the Startup folder above.")
                else:
                    severity = "LOW"
                    note = ("Normal startup shortcut. The Target column shows what "
                            "it launches — if that program is one you expect, it is "
                            "safe to keep. To remove it: delete this .lnk from the "
                            "Startup folder above, or use Task Manager \u2192 Startup apps.")
            elif ext in HIGH_RISK_STARTUP_EXTS:
                flags.append("SCRIPT_IN_STARTUP")
                severity = "HIGH"
                note = ("A script set to auto-run at logon is a common persistence "
                        "technique. Open the file (Right-click \u2192 Edit) to review what "
                        "it does. If unexpected, delete it from the Startup folder.")
            elif ext in EXEC_STARTUP_EXTS:
                flags.append("EXECUTABLE_IN_STARTUP")
                severity = "MEDIUM"
                note = ("An executable auto-runs at logon. Confirm it is a program "
                        "you installed and that it is digitally signed (Right-click "
                        "\u2192 Properties \u2192 Digital Signatures).")
            else:
                severity = "LOW"
                note = "Data/support file — typically benign."

            if recently:
                flags.append("RECENTLY_MODIFIED")
                if severity == "LOW":
                    severity = "MEDIUM"
                note += (" Note: this item was modified within the last "
                         f"{RECENT_HOURS}h — unexpected recent changes warrant a closer look.")

            items_info.append({
                "name": item.name,
                "full_path": full_path,
                "ext": ext,
                "size_bytes": st.st_size if st else None,
                "modified": _fmt_ts(st.st_mtime) if st else "N/A",
                "target": target,
                "target_args": args,
                "flags": flags,
                "severity": severity,
                "note": note,
            })

        _sev_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        items_info.sort(key=lambda x: _sev_rank.get(x["severity"], 3))

        findings.append({
            "scope": scope,
            "owner": owner,
            "path": path,
            "accessible": True,
            "item_count": len(items_info),
            "suspicious_count": sum(1 for i in items_info if i["severity"] == "HIGH"),
            "items": items_info,
        })

    return {"locations": findings}


def _users_dirs(users_root: str = r"C:\Users") -> list[Path]:
    try:
        return [d for d in Path(users_root).iterdir()
                if d.is_dir() and d.name.lower() not in ("all users", "default user")]
    except (PermissionError, OSError):
        return []


def find_hive_copies(search_dirs: list[str] | None = None,
                     users_root: str = r"C:\Users") -> list[dict]:
    """Look for exported SAM/SYSTEM/SECURITY hives or ntds.dit outside System32.

    Only the top level of each folder is listed (no recursion, nothing opened),
    so this stays fast and read-only.
    """
    dirs = list(search_dirs if search_dirs is not None else HIVE_COPY_DIRS)
    for ud in _users_dirs(users_root):
        dirs += [str(ud / sub) for sub in HIVE_COPY_USER_DIRS]

    hits, seen = [], set()
    for d in dirs:
        try:
            with os.scandir(d) as it:
                for e in it:
                    if not e.is_file(follow_symlinks=False):
                        continue
                    if e.name.lower() not in HIVE_COPY_NAMES:
                        continue
                    real = os.path.normcase(os.path.abspath(e.path))
                    if real in seen or "\\system32\\config\\" in real.lower():
                        continue
                    seen.add(real)
                    st = _safe_stat(e.path)
                    hits.append({
                        "path": e.path,
                        "name": e.name,
                        "size_bytes": st.st_size if st else None,
                        "modified": _fmt_ts(st.st_mtime) if st else "N/A",
                    })
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            continue
    return hits


def scan_credential_stores() -> dict:
    """Credential hives: report status, and flag exported copies (offline cracking)."""
    hives = [
        (r"C:\Windows\System32\config\SAM",      "SAM (local password hashes)"),
        (r"C:\Windows\System32\config\SECURITY", "SECURITY (policies & LSA secrets)"),
        (r"C:\Windows\System32\config\SYSTEM",   "SYSTEM hive (holds the SAM boot key)"),
        (r"C:\Windows\System32\config\SOFTWARE", "SOFTWARE hive"),
    ]
    findings = []
    # The live hives change constantly while Windows runs, so their timestamps
    # are informational only — they are never a finding by themselves.
    for path, label in hives:
        st = _safe_stat(path)
        findings.append({
            "path": path,
            "label": label,
            "accessible": st is not None,
            "size_bytes": st.st_size if st else None,
            "modified": _fmt_ts(st.st_mtime) if st else "N/A",
            "flags": [],
            "severity": "INFO",
            "note": "Live hive in use by Windows (expected).",
        })

    for hit in find_hive_copies():
        findings.insert(0, {
            "path": hit["path"],
            "label": f"Exported hive copy: {hit['name']}",
            "accessible": True,
            "size_bytes": hit["size_bytes"],
            "modified": hit["modified"],
            "flags": ["HIVE_COPY_OUTSIDE_CONFIG"],
            "severity": "HIGH",
            "note": ("A copy of a credential hive outside System32\\config is a classic "
                     "sign of password-hash theft (reg save / shadow copy). If you did not "
                     "create it, treat this PC as compromised and change local passwords."),
        })

    return {
        "findings": findings,
        "suspicious_count": sum(1 for f in findings if f["severity"] == "HIGH"),
    }


# Log-clearing events: Security 1102 = "audit log was cleared",
# System 104 = "an event log was cleared".
LOG_CLEAR_QUERIES = [
    ("Security", 1102, "The Security audit log was cleared"),
    ("System", 104, "An event log was cleared"),
]


def _run_wevtutil(args: list[str], timeout: int = 20) -> str | None:
    """Run wevtutil read-only (query only); None if unavailable/denied."""
    if os.name != "nt":
        return None
    try:
        out = subprocess.run(
            ["wevtutil.exe", *args],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def parse_clear_events(xml_text: str) -> list[str]:
    """Pull SystemTime values out of wevtutil /f:xml output."""
    import re
    return re.findall(r"SystemTime=['\"]([^'\"]+)['\"]", xml_text or "")


def find_log_clearing(lookback_days: int = LOG_CLEAR_LOOKBACK_DAYS) -> dict:
    """Query Security 1102 / System 104 events within the look-back window."""
    ms = lookback_days * 24 * 3600 * 1000
    results, available = [], False
    for channel, event_id, label in LOG_CLEAR_QUERIES:
        query = f"*[System[(EventID={event_id}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
        xml = _run_wevtutil(["qe", channel, f"/q:{query}", "/c:20", "/rd:true", "/f:xml"])
        if xml is None:
            continue
        available = True
        for ts in parse_clear_events(xml):
            results.append({"channel": channel, "event_id": event_id,
                            "label": label, "time": ts})
    return {"available": available, "events": results}


def scan_event_logs(evtx_dir: str = r"C:\Windows\System32\winevt\Logs",
                    clearing: dict | None = None) -> dict:
    """Event-log health.

    Evidence of clearing comes from the clearing events themselves (Security
    1102, System 104). File size alone is NOT used for most logs: every unused
    log is exactly 68 KB (69,632 bytes), which used to flood the report.
    An empty Security or System log is still flagged, because those two are
    written to constantly on any real PC.
    """
    CRITICAL_LOGS = {"security.evtx", "system.evtx", "application.evtx",
                     "microsoft-windows-powershell%4operational.evtx",
                     "microsoft-windows-sysmon%4operational.evtx",
                     "microsoft-windows-taskscheduler%4operational.evtx",
                     "microsoft-windows-bits-client%4operational.evtx",
                     "microsoft-windows-winrm%4operational.evtx"}
    ALWAYS_BUSY = {"security.evtx", "system.evtx"}

    try:
        with os.scandir(evtx_dir) as it:
            evtx_files = [Path(e.path) for e in it if e.name.lower().endswith(".evtx")]
    except (PermissionError, FileNotFoundError, OSError):
        return {"accessible": False, "path": evtx_dir, "findings": [], "clear_events": [],
                "possibly_cleared": 0,
                "summary": "Permission denied — run WSTS as Administrator to read event logs"}

    if clearing is None:
        clearing = find_log_clearing()

    findings = []
    for evtx in evtx_files:
        name_lower = evtx.name.lower()
        is_critical = name_lower in CRITICAL_LOGS
        if not is_critical:
            continue  # hundreds of rarely-used logs: not useful in this view
        st = _safe_stat(str(evtx))
        if not st:
            continue
        flags = ["CRITICAL_LOG"]
        severity = "INFO"
        if name_lower in ALWAYS_BUSY and st.st_size <= EMPTY_EVTX_BYTES:
            flags.append("EMPTY_BUSY_LOG")
            severity = "HIGH"

        findings.append({
            "file": evtx.name,
            "path": str(evtx),
            "size_bytes": st.st_size,
            "size_kb": round(st.st_size / 1024, 1),
            "modified": _fmt_ts(st.st_mtime),
            "age_hours": round(_age_hours(st.st_mtime), 1),
            "flags": flags,
            "severity": severity,
            "is_critical": True,
        })

    for ev in clearing.get("events", []):
        findings.insert(0, {
            "file": f"{ev['channel']} — Event {ev['event_id']}",
            "path": ev["channel"],
            "size_bytes": None,
            "size_kb": None,
            "modified": ev["time"],
            "age_hours": None,
            "flags": ["LOG_CLEARED"],
            "severity": "HIGH",
            "is_critical": True,
            "note": ev["label"] + ". Attackers clear logs to hide activity; if no one on "
                    "your team cleared them on purpose, investigate.",
        })

    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda x: rank.get(x["severity"], 4))

    cleared = sum(1 for f in findings if f["severity"] == "HIGH")
    return {
        "accessible": True,
        "path": evtx_dir,
        "total": len(evtx_files),
        "possibly_cleared": cleared,
        "clear_check_available": clearing.get("available", False),
        "clear_lookback_days": LOG_CLEAR_LOOKBACK_DAYS,
        "findings": findings,
    }


def scan_amcache_ntuser(users_root: str = r"C:\Users") -> dict:
    """Amcache.hve and per-user NTUSER.DAT status (informational).

    These files are rewritten during normal use, so a recent timestamp is
    shown for context but never raises the severity.
    """
    results = []

    amcache = r"C:\Windows\AppCompat\Programs\Amcache.hve"
    st = _safe_stat(amcache)
    results.append({
        "label": "Amcache.hve (application execution history)",
        "path": amcache,
        "accessible": st is not None,
        "size_bytes": st.st_size if st else None,
        "modified": _fmt_ts(st.st_mtime) if st else "N/A",
        "age_hours": round(_age_hours(st.st_mtime), 1) if st else None,
        "flags": [],
        "severity": "INFO",
    })

    for ud in _users_dirs(users_root):
        ntuser = ud / "NTUSER.DAT"
        st = _safe_stat(str(ntuser))
        if st is None and not (ud / "AppData").exists():
            continue  # not a real profile folder
        results.append({
            "label": f"NTUSER.DAT — {ud.name}",
            "path": str(ntuser),
            "accessible": st is not None,
            "size_bytes": st.st_size if st else None,
            "modified": _fmt_ts(st.st_mtime) if st else "N/A (locked or missing)",
            "age_hours": round(_age_hours(st.st_mtime), 1) if st else None,
            "flags": [],
            "severity": "INFO",
        })

    return {"findings": results}


def run_full_scan() -> dict:
    return {
        "scan_time": _now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "host": os.environ.get("COMPUTERNAME", "unknown"),
        "version": __version__,
        "rules_version": RULES.get("version", "unknown"),
        "elevated": is_admin(),
        "prefetch":     scan_prefetch(),
        "startup":      scan_startup_persistence(),
        "credentials":  scan_credential_stores(),
        "event_logs":   scan_event_logs(),
        "amcache_ntuser": scan_amcache_ntuser(),
    }

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows Security Threat Scanner</title>
<style nonce="{{ nonce }}">
  :root{
    --bg:#0d1117;--panel:#161b22;--border:#30363d;
    --red:#ff4c4c;--orange:#e69240;--yellow:#e3b341;
    --green:#3fb950;--blue:#58a6ff;--gray:#8b949e;
    --text:#c9d1d9;--white:#f0f6fc;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}
  header{background:var(--panel);border-bottom:1px solid var(--border);
    padding:16px 24px;display:flex;align-items:center;justify-content:space-between}
  header h1{color:var(--white);font-size:1.3rem;letter-spacing:.5px}
  header span{color:var(--gray);font-size:.8rem}
  #scan-btn{background:var(--blue);color:#000;border:none;padding:8px 20px;
    border-radius:6px;font-weight:700;cursor:pointer;font-size:.9rem}
  #scan-btn:hover{opacity:.85}
  #scan-btn:disabled{opacity:.4;cursor:default}
  #quit-btn{background:transparent;color:var(--gray);border:1px solid var(--border);padding:7px 14px;
    border-radius:6px;cursor:pointer;font-size:.85rem}
  #quit-btn:hover{color:var(--white);border-color:var(--gray)}
  #status{color:var(--gray);font-size:.8rem;margin-left:12px}

  main{padding:20px 24px;max-width:1400px;margin:auto}

  .summary-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
  .badge{border-radius:8px;padding:12px 18px;min-width:160px;text-align:center}
  .badge .num{font-size:2rem;font-weight:700}
  .badge .lbl{font-size:.75rem;color:var(--gray)}
  .badge.red{background:#2d1a1a;border:1px solid var(--red)}  .badge.red .num{color:var(--red)}
  .badge.orange{background:#2b1e10;border:1px solid var(--orange)} .badge.orange .num{color:var(--orange)}
  .badge.green{background:#0d1f12;border:1px solid var(--green)} .badge.green .num{color:var(--green)}
  .badge.blue{background:#0d1a2b;border:1px solid var(--blue)} .badge.blue .num{color:var(--blue)}

  section{background:var(--panel);border:1px solid var(--border);border-radius:10px;
    margin-bottom:20px;overflow:hidden}
  section .sec-header{
    background:#1c2128;padding:12px 18px;display:flex;align-items:center;
    justify-content:space-between;cursor:pointer;user-select:none}
  section .sec-header h2{font-size:1rem;color:var(--white)}
  section .sec-body{padding:0}

  table{width:100%;border-collapse:collapse}
  thead tr{background:#1c2128}
  th{padding:8px 12px;text-align:left;color:var(--gray);font-weight:600;
    font-size:.8rem;border-bottom:1px solid var(--border)}
  td{padding:7px 12px;border-bottom:1px solid #1c2128;vertical-align:top}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#1c2128}

  .sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700}
  .sev.HIGH{background:#2d1a1a;color:var(--red);border:1px solid var(--red)}
  .sev.MEDIUM{background:#2b1e10;color:var(--orange);border:1px solid var(--orange)}
  .sev.LOW,.sev.INFO{background:#111;color:var(--gray);border:1px solid #333}

  .flag{display:inline-block;margin:1px 3px 1px 0;padding:1px 6px;border-radius:3px;
    font-size:.7rem;background:#1c2128;border:1px solid var(--border);color:var(--yellow)}
  .flag.KNOWN_OFFENSIVE_TOOL,.flag.LOG_CLEARED,.flag.EMPTY_BUSY_LOG,.flag.HIVE_COPY_OUTSIDE_CONFIG{color:var(--red);border-color:var(--red)}
  .flag.DUAL_USE_TOOL,.flag.RECENT_DUAL_USE{color:var(--orange);border-color:var(--orange)}
  .flag.BUILTIN_TOOL{color:var(--gray);border-color:#333}
  .flag.RECENTLY_MODIFIED,.flag.RAN_LAST_1H,.flag.RAN_LAST_24H{color:var(--orange);border-color:var(--orange)}
  .flag.SUSPICIOUS_EXTENSION,.flag.SCRIPT_IN_STARTUP,.flag.SUSPICIOUS_LNK_TARGET{color:var(--red);border-color:var(--red)}
  .flag.EXECUTABLE_IN_STARTUP{color:var(--yellow);border-color:var(--yellow)}
  .flag.CRITICAL_LOG{color:var(--blue);border-color:var(--blue)}

  .path{font-size:.75rem;color:var(--gray);font-family:monospace}
  .inaccessible{color:var(--gray);font-style:italic;padding:12px 18px}
  .scope-label{font-size:.8rem;font-weight:700;color:var(--blue);padding:8px 12px 4px;
    border-bottom:1px solid var(--border);background:#0d1117}
  .no-items{color:var(--gray);padding:10px 18px;font-style:italic}
  .guide-note{font-size:.8rem;color:var(--text);background:#0d1a2b;border:1px solid var(--blue);
    border-radius:8px;padding:10px 14px;margin:0 0 12px;line-height:1.5}

  .chevron{font-size:.8rem;color:var(--gray);transition:transform .2s}
  .collapsed .chevron{transform:rotate(-90deg)}
  .sec-body.hidden{display:none}
  @keyframes spin{to{transform:rotate(360deg)}}
  #spinner{display:none;margin-left:10px;color:var(--blue);font-weight:700}
  #spinner.on{display:inline-block;animation:spin .9s linear infinite}
  #scan-banner{display:none;align-items:center;gap:14px;background:#0d1a2b;
    border:1px solid var(--blue);border-radius:10px;padding:14px 20px;
    margin-bottom:20px;color:var(--white)}
  #scan-banner.on{display:flex}
  #scan-banner .ring{width:22px;height:22px;flex-shrink:0;border:3px solid #1c3a5e;
    border-top-color:var(--blue);border-radius:50%;animation:spin .8s linear infinite}
  .ready-prompt{width:100%;background:#0d1a2b;border:1px solid var(--blue);
    border-radius:10px;padding:16px 20px;color:var(--text)}
  .ready-prompt b{color:var(--white)}

  /* scrollable large tables */
  .scroll-wrap{max-height:480px;overflow-y:auto}
  .scroll-wrap::-webkit-scrollbar{width:6px}
  .scroll-wrap::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

  .app-footer{margin-top:32px;padding:20px 24px;border-top:1px solid var(--border);
    text-align:center;color:var(--gray)}
  .app-footer .footer-tagline{color:var(--text);font-size:0.95rem;margin:0 0 6px}
  .app-footer .footer-tagline b{color:var(--white)}
  .app-footer p{margin:4px 0;font-size:0.82rem}
  .elev-warn{width:100%;background:#2b1e10;border:1px solid var(--orange);border-radius:10px;
    padding:12px 18px;color:var(--white);margin-bottom:16px}
  .note{color:var(--gray);font-size:.76rem;margin-top:4px;line-height:1.4}
</style>
</head>
<body>
<header>
  <h1>{% if shield_uri %}<img src="{{ shield_uri }}" alt="WSTS shield" style="height:44px;width:44px;vertical-align:-11px;margin-right:12px">{% else %}&#x1F6E1; {% endif %}Windows Security Threat Scanner - WSTS</h1>
  <div style="display:flex;align-items:center;gap:8px">
    <span id="scan-time"></span>
    <span id="spinner">&#9696;</span>
    <button id="scan-btn" type="button">&#x21BA; Scan Now</button>
    <button id="quit-btn" type="button" title="Stop WSTS">Quit</button>
  </div>
</header>

<main>
  <div id="elev"></div>
  <div id="scan-banner">
    <div class="ring"></div>
    <div><b>Scanning your system&hellip;</b> inspecting Prefetch, Startup, Event Logs,
    Credential hives &amp; Amcache. Everything runs locally &mdash; nothing leaves this PC.</div>
  </div>
  <div class="summary-row" id="summary"></div>

  <section id="sec-prefetch">
    <div class="sec-header" data-toggle="sec-prefetch">
      <h2>&#x1F5C4; Malware &amp; Threat Indicators — Prefetch</h2>
      <span class="chevron">&#9660;</span>
    </div>
    <div class="sec-body" id="body-prefetch"><div class="inaccessible">Run scan to load…</div></div>
  </section>

  <section id="sec-startup">
    <div class="sec-header" data-toggle="sec-startup">
      <h2>&#x23F0; Persistence &amp; Startup Locations</h2>
      <span class="chevron">&#9660;</span>
    </div>
    <div class="sec-body" id="body-startup"><div class="inaccessible">Run scan to load…</div></div>
  </section>

  <section id="sec-evtx">
    <div class="sec-header" data-toggle="sec-evtx">
      <h2>&#x1F4CB; Event Log Health</h2>
      <span class="chevron">&#9660;</span>
    </div>
    <div class="sec-body" id="body-evtx"><div class="inaccessible">Run scan to load…</div></div>
  </section>

  <section id="sec-creds">
    <div class="sec-header" data-toggle="sec-creds">
      <h2>&#x1F512; Credential &amp; Registry Hive Integrity</h2>
      <span class="chevron">&#9660;</span>
    </div>
    <div class="sec-body" id="body-creds"><div class="inaccessible">Run scan to load…</div></div>
  </section>

  <section id="sec-amcache">
    <div class="sec-header" data-toggle="sec-amcache">
      <h2>&#x1F4BE; Amcache &amp; NTUSER.DAT</h2>
      <span class="chevron">&#9660;</span>
    </div>
    <div class="sec-body" id="body-amcache"><div class="inaccessible">Run scan to load…</div></div>
  </section>
</main>

<footer class="app-footer">
  <p class="footer-tagline">&#x1F6E1; <b>Built for defenders</b> &middot; Antibody Cyber Technology, LLC</p>
  <p>&copy; 2026 Antibody Cyber Technology, LLC &middot; WSTS v{{ version }} &middot; rules {{ rules_version }}</p>
</footer>

<script nonce="{{ nonce }}">
"use strict";
function esc(s){return (s==null?'':String(s)).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
const SEVS=new Set(['HIGH','MEDIUM','LOW','INFO']);
function sev(s){s=SEVS.has(s)?s:'INFO';return `<span class="sev ${s}">${s}</span>`}
function flags(arr){return (arr||[]).map(f=>{const c=String(f).replace(/[^A-Z0-9_]/g,'');return `<span class="flag ${c}">${esc(f)}</span>`}).join('')}
function kb(b){return b==null?'—':(b/1024).toFixed(1)+' KB'}

function toggleSection(id){
  const sec=document.getElementById(id);
  const body=sec.querySelector('.sec-body');
  sec.classList.toggle('collapsed');
  body.classList.toggle('hidden');
}

function renderSummary(d){
  const pf=d.prefetch, el=d.event_logs, cr=d.credentials;
  const offensive = pf.suspicious_count ?? 0;
  const dual      = pf.dual_use_count ?? 0;
  const cleared   = el.possibly_cleared ?? 0;
  const hives     = cr.suspicious_count ?? 0;
  const startupH  = d.startup.locations.reduce((a,l)=>a+(l.suspicious_count||0),0);
  document.getElementById('summary').innerHTML=`
    <div class="badge ${offensive>0?'red':'green'}">
      <div class="num">${offensive}</div><div class="lbl">Offensive Tools Run</div></div>
    <div class="badge ${dual>0?'orange':'green'}">
      <div class="num">${dual}</div><div class="lbl">Dual-use Admin Tools</div></div>
    <div class="badge ${cleared>0?'red':'green'}">
      <div class="num">${cleared}</div><div class="lbl">Log Clearing / Empty Logs</div></div>
    <div class="badge ${startupH>0?'orange':'green'}">
      <div class="num">${startupH}</div><div class="lbl">Suspicious Startup Items</div></div>
    <div class="badge ${hives>0?'red':'green'}">
      <div class="num">${hives}</div><div class="lbl">Exported Hive Copies</div></div>
  `;
  document.getElementById('scan-time').textContent='Last scan: '+d.scan_time+' | Host: '+d.host;
  document.getElementById('elev').innerHTML = d.elevated ? '' :
    '<div class="elev-warn"><b>Not running as Administrator.</b> Prefetch and event-log checks '+
    'need admin rights, so some sections may be empty. Close WSTS, then right-click it and choose '+
    '<b>Run as administrator</b> for a complete scan.</div>';
}

function renderPrefetch(pf){
  const el=document.getElementById('body-prefetch');
  if(!pf.accessible){el.innerHTML=`<div class="inaccessible">${esc(pf.summary)}</div>`;return}
  if(!pf.findings.length){el.innerHTML='<div class="no-items">No prefetch files found.</div>';return}
  const rows=pf.findings.map(f=>`<tr>
    <td>${sev(f.severity)}</td>
    <td style="font-family:monospace">${esc(f.exe)}</td>
    <td>${esc(f.last_run)}</td>
    <td>${esc(f.age_hours)}h</td>
    <td>${kb(f.size_bytes)}</td>
    <td>${flags(f.flags)||'—'}</td>
  </tr>`).join('');
  el.innerHTML=`<div class="guide-note"><b>HIGH</b> = known attack/credential-theft tool. <b>MEDIUM</b> = legitimate admin tool attackers often abuse; confirm you or your IT staff ran it. Built-in Windows tools (cmd, PowerShell, whoami&hellip;) are listed for context only.</div>
    <div class="scroll-wrap"><table>
    <thead><tr><th>SEV</th><th>Executable</th><th>Last Run</th><th>Age</th><th>Size</th><th>Flags</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function renderStartup(startup){
  const el=document.getElementById('body-startup');
  let html='<div class="guide-note">Each item shows <b>what it launches</b> (Target / Command) and <b>how to remediate</b> it. '+
    'To remove a startup entry: delete its file from the folder shown, or open <b>Task Manager → Startup apps</b>. '+
    'Verify a target is genuine via <b>Right-click → Properties → Digital Signatures</b>.</div>';
  for(const loc of startup.locations){
    html+=`<div class="scope-label">${loc.scope==='global'?'&#x1F310;':
      '&#x1F464;'} ${esc(loc.owner)} — <span class="path">${esc(loc.path)}</span></div>`;
    if(!loc.accessible){html+=`<div class="inaccessible">Inaccessible: ${esc(loc.error)}</div>`;continue}
    if(!loc.items.length){html+='<div class="no-items">Empty — no startup items.</div>';continue}
    const rows=loc.items.map(i=>{
      const tgt = i.target
        ? `<div style="font-family:monospace;font-size:.78rem">${esc(i.target)}`+
          `${i.target_args?` <span style="color:var(--orange)">${esc(i.target_args)}</span>`:''}</div>`
        : '<span style="color:var(--gray)">— (not a shortcut)</span>';
      const note = i.note ? `<div class="note">${esc(i.note)}</div>` : '';
      return `<tr>
        <td>${sev(i.severity)}</td>
        <td><div style="font-family:monospace" title="${esc(i.full_path)}">${esc(i.name)}</div>
          <div style="color:var(--gray);font-size:.72rem">${esc(i.full_path)}</div>${note}</td>
        <td>${tgt}</td>
        <td>${esc(i.modified)}</td>
        <td>${flags(i.flags)||'—'}</td>
      </tr>`;
    }).join('');
    html+=`<table><thead><tr><th>SEV</th><th>File / Location</th><th>Target / Command</th><th>Modified</th><th>Flags</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }
  el.innerHTML=html;
}

function renderEvtx(d){
  const el=document.getElementById('body-evtx');
  if(!d.accessible){el.innerHTML=`<div class="inaccessible">${esc(d.summary)}</div>`;return}
  const clearNote = d.clear_check_available
    ? `Checked the last ${esc(d.clear_lookback_days)} days for log-clearing events (Security 1102, System 104).`
    : 'Could not query log-clearing events (run as Administrator for this check).';
  const rows=d.findings.map(f=>`<tr>
    <td>${sev(f.severity)}</td>
    <td style="font-family:monospace;font-size:.8rem">${esc(f.file)}${f.note?`<div class="note">${esc(f.note)}</div>`:''}</td>
    <td>${f.size_kb==null?'—':esc(f.size_kb)+' KB'}</td>
    <td>${esc(f.modified)}</td>
    <td>${flags(f.flags)||'—'}</td>
  </tr>`).join('');
  el.innerHTML=`<div class="guide-note">${clearNote} Showing the ${d.findings.length} security-relevant logs out of ${esc(d.total)} on this PC.</div>
    <div class="scroll-wrap"><table>
    <thead><tr><th>SEV</th><th>Log / Event</th><th>Size</th><th>Modified / Time</th><th>Flags</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function renderCreds(creds){
  const el=document.getElementById('body-creds');
  const rows=creds.findings.map(f=>`<tr>
    <td>${sev(f.severity||'INFO')}</td>
    <td>${esc(f.label)}${f.note?`<div class="note">${esc(f.note)}</div>`:''}</td>
    <td class="path">${esc(f.path)}</td>
    <td>${f.accessible?kb(f.size_bytes):'<span style="color:var(--gray)">Locked/denied (expected)</span>'}</td>
    <td>${esc(f.modified||'—')}</td>
    <td>${flags(f.flags)||'—'}</td>
  </tr>`).join('');
  el.innerHTML=`<div class="guide-note">The live hives are always in use, so their timestamps are informational. WSTS looks for <b>exported copies</b> of these hives (or ntds.dit) in Temp, Public, Desktop, Downloads and similar folders, a common step in password-hash theft.</div>
    <table>
    <thead><tr><th>SEV</th><th>Store</th><th>Path</th><th>Size</th><th>Modified</th><th>Flags</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function renderAmcache(ac){
  const el=document.getElementById('body-amcache');
  const rows=ac.findings.map(f=>`<tr>
    <td>${sev(f.severity)}</td>
    <td>${esc(f.label)}</td>
    <td class="path">${esc(f.path)}</td>
    <td>${f.accessible?kb(f.size_bytes):'<span style="color:var(--gray)">Locked/denied</span>'}</td>
    <td>${esc(f.modified||'—')}</td>
    <td>${flags(f.flags)||'—'}</td>
  </tr>`).join('');
  el.innerHTML=`<div class="scroll-wrap"><table>
    <thead><tr><th>SEV</th><th>Artifact</th><th>Path</th><th>Size</th><th>Modified</th><th>Flags</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

async function runScan(){
  const btn=document.getElementById('scan-btn');
  const spin=document.getElementById('spinner');
  const banner=document.getElementById('scan-banner');
  const started=Date.now();
  btn.disabled=true; btn.textContent='⟳ Scanning…';
  spin.classList.add('on'); banner.classList.add('on');
  ['prefetch','startup','evtx','creds','amcache'].forEach(id=>{
    const b=document.getElementById('body-'+id);
    if(b) b.innerHTML='<div class="inaccessible">Scanning…</div>';
  });
  try{
    const r=await fetch('/api/scan',{credentials:'same-origin',headers:{'X-WSTS':'1'}});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const d=await r.json();
    renderSummary(d);
    renderPrefetch(d.prefetch);
    renderStartup(d.startup);
    renderEvtx(d.event_logs);
    renderCreds(d.credentials);
    renderAmcache(d.amcache_ntuser);
  }catch(e){
    document.getElementById('summary').innerHTML=
      `<div class="elev-warn"><b>Scan failed:</b> ${esc(e.message)}. Close WSTS and start it again from the Start menu.</div>`;
  }finally{
    const finish=()=>{
      btn.disabled=false; btn.innerHTML='&#x21BA; Scan Now';
      spin.classList.remove('on'); banner.classList.remove('on');
    };
    const elapsed=Date.now()-started;
    if(elapsed<800){ setTimeout(finish, 800-elapsed); } else { finish(); }
  }
}

window.addEventListener('DOMContentLoaded', function(){
  document.getElementById('scan-btn').addEventListener('click', runScan);
  document.getElementById('quit-btn').addEventListener('click', async ()=>{
    try{ await fetch('/api/quit',{method:'POST',credentials:'same-origin',headers:{'X-WSTS':'1'}}); }catch(e){}
    document.body.innerHTML='<main><div class="ready-prompt">WSTS has stopped. You can close this tab.</div></main>';
  });
  document.querySelectorAll('[data-toggle]').forEach(h=>
    h.addEventListener('click', ()=>toggleSection(h.dataset.toggle)));
  document.getElementById('summary').innerHTML=
    '<div class="ready-prompt">Ready. Click <b>Scan Now</b> to inspect this PC. '+
    'WSTS performs a <b>read-only</b> scan entirely on your machine and never uploads anything.</div>';
  // Drop the session token from the address bar once the cookie is set.
  if (location.search) history.replaceState(null, '', '/');
});
</script>
</body>
</html>
"""


def _shield_data_uri() -> str:
    """Return the bundled WSTS shield as a base64 data URI (empty if missing)."""
    import base64

    base = _resource_dir()
    for path in (os.path.join(base, "static", "img", "wsts_shield.png"),
                 os.path.join(base, "wsts_shield.png")):
        try:
            with open(path, "rb") as fh:
                return "data:image/png;base64," + base64.b64encode(fh.read()).decode("ascii")
        except OSError:
            continue
    return ""


# ---------------------------------------------------------------------------
# Local-dashboard protections
# ---------------------------------------------------------------------------

def allowed_hosts(port: int) -> set[str]:
    return {f"127.0.0.1:{port}", f"localhost:{port}"}


def _token_ok(value: str | None) -> bool:
    return bool(value) and secrets.compare_digest(value, SESSION_TOKEN)


@app.before_request
def _guard():
    # 1. Host header must be loopback: defeats DNS-rebinding attacks where a
    #    web page points its own hostname at 127.0.0.1 to read the dashboard.
    if request.host not in allowed_hosts(BOUND_PORT):
        abort(403)
    # 2. Everything except the entry page needs the session cookie.
    if request.endpoint == "index":
        return None
    if not _token_ok(request.cookies.get(COOKIE_NAME)):
        abort(403)
    # 3. The scan API is only called by our own page (custom header => no
    #    simple cross-site request can trigger it).
    if request.endpoint in ("api_scan", "api_quit") and request.headers.get("X-WSTS") != "1":
        abort(403)
    return None


@app.after_request
def _security_headers(resp):
    nonce = g.get("wsts_nonce")
    script_src = f"'nonce-{nonce}'" if nonce else "'none'"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        f"script-src {script_src}; "
        "style-src 'unsafe-inline'; "  # inline style attributes in rendered tables
        "img-src data:; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return resp


@app.errorhandler(403)
def _forbidden(_e):
    return ("WSTS: this dashboard only opens from the WSTS app on this PC. "
            "Start WSTS from the Start menu to open it.", 403,
            {"Content-Type": "text/plain; charset=utf-8"})


@app.route("/")
def index():
    token = request.args.get("t")
    if not (_token_ok(token) or _token_ok(request.cookies.get(COOKIE_NAME))):
        abort(403)
    nonce = secrets.token_urlsafe(16)
    g.wsts_nonce = nonce
    resp = make_response(render_template_string(
        HTML_TEMPLATE, shield_uri=_shield_data_uri(), nonce=nonce,
        version=__version__, rules_version=RULES.get("version", "unknown")))
    resp.set_cookie(COOKIE_NAME, SESSION_TOKEN, httponly=True, samesite="Strict",
                    path="/")
    return resp


@app.route("/api/scan")
def api_scan():
    """Return full scan results as JSON."""
    return jsonify(run_full_scan())


@app.route("/api/quit", methods=["POST"])
def api_quit():
    """Stop WSTS (the windowed build has no console to close)."""
    import threading
    _clear_instance()
    threading.Timer(0.3, lambda: os._exit(0)).start()
    return jsonify({"stopping": True})


# ---------------------------------------------------------------------------
# Startup: single instance, port selection, session file
# ---------------------------------------------------------------------------

def _instance_file() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "WSTS", "instance.json")


def _read_instance() -> dict | None:
    try:
        with open(_instance_file(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _write_instance(port: int) -> None:
    path = _instance_file()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"port": port, "token": SESSION_TOKEN, "pid": os.getpid()}, fh)
    except OSError:
        pass


def _clear_instance() -> None:
    data = _read_instance()
    if data and data.get("pid") == os.getpid():
        try:
            os.remove(_instance_file())
        except OSError:
            pass


def _port_in_use(host: str, port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _free_port(host: str) -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def main() -> None:
    global BOUND_PORT
    import atexit
    import threading
    import webbrowser

    host = "127.0.0.1"

    # In a windowed (--noconsole) PyInstaller build, sys.stdout/stderr are None.
    # Werkzeug writes to stderr, so give it a real sink to avoid silent crashes.
    if sys.stdout is None or sys.stderr is None:
        try:
            log_path = os.path.join(os.environ.get("TEMP", os.path.expanduser("~")), "wsts.log")
            _sink = open(log_path, "a", buffering=1, encoding="utf-8")
        except Exception:
            _sink = open(os.devnull, "w")
        if sys.stdout is None:
            sys.stdout = _sink
        if sys.stderr is None:
            sys.stderr = _sink

    # Already running? Re-open that instance's dashboard and exit.
    inst = _read_instance()
    if inst and isinstance(inst.get("port"), int) and _port_in_use(host, inst["port"]):
        webbrowser.open(f"http://{host}:{inst['port']}/?t={inst.get('token', '')}")
        sys.exit(0)

    port = DEFAULT_PORT if not _port_in_use(host, DEFAULT_PORT) else _free_port(host)
    BOUND_PORT = port
    _write_instance(port)
    atexit.register(_clear_instance)

    url = f"http://{host}:{port}/?t={SESSION_TOKEN}"
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    print("=" * 60)
    print(f"  Windows Security Threat Scanner (WSTS) v{__version__}")
    print(f"  http://{host}:{port}/")
    print("  Running as Administrator" if is_admin() else
          "  NOTE: Run as Administrator for full access")
    print("=" * 60)

    try:
        app.run(host=host, port=port, debug=False, use_reloader=False)
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - last-resort visibility
        print(f"WSTS failed to start: {exc}")
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
                None, f"WSTS could not start the local dashboard.\n\n{exc}", "WSTS", 0x10)
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
