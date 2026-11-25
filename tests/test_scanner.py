"""Tests for WSTS scan logic and dashboard protections.

Run:  python -m pytest -q
The scanners are pointed at temporary folders, so these tests run on any OS.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import win_scanner_app as w  # noqa: E402

EMPTY = w.EMPTY_EVTX_BYTES


def _touch(path, size=0, age_hours=0.0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"\0" * size)
    t = time.time() - age_hours * 3600
    os.utime(path, (t, t))


# ---------------------------------------------------------------- prefetch

@pytest.mark.parametrize("name,expected", [
    ("MIMIKATZ.EXE-1A2B3C4D.pf", "MIMIKATZ.EXE"),
    ("ADVANCED_PORT_SCANNER.EXE-00AA11BB.pf", "ADVANCED_PORT_SCANNER.EXE"),
    ("MY-TOOL.EXE-DEADBEEF.pf", "MY-TOOL.EXE"),
    ("WEIRD.pf", "WEIRD"),
])
def test_prefetch_exe_name(name, expected):
    assert w.prefetch_exe_name(name) == expected


def test_classify_tiers():
    assert w.classify_prefetch("MIMIKATZ.EXE") == ("KNOWN_OFFENSIVE_TOOL", "HIGH")
    assert w.classify_prefetch("PSEXEC.EXE") == ("DUAL_USE_TOOL", "MEDIUM")
    assert w.classify_prefetch("CMD.EXE") == ("BUILTIN_TOOL", "INFO")
    assert w.classify_prefetch("POWERSHELL.EXE") == ("BUILTIN_TOOL", "INFO")
    assert w.classify_prefetch("CHROME.EXE") == (None, None)


def test_scan_prefetch_counts(tmp_path):
    d = tmp_path / "Prefetch"
    _touch(str(d / "MIMIKATZ.EXE-11111111.pf"), 100, age_hours=2)
    _touch(str(d / "PSEXEC.EXE-22222222.pf"), 100, age_hours=3)
    _touch(str(d / "CMD.EXE-33333333.pf"), 100, age_hours=0.5)
    _touch(str(d / "WHOAMI.EXE-44444444.pf"), 100, age_hours=5)
    _touch(str(d / "CHROME.EXE-55555555.pf"), 100, age_hours=48)
    r = w.scan_prefetch(str(d))
    assert r["accessible"] and r["total"] == 5
    assert r["suspicious_count"] == 1          # only mimikatz is HIGH
    assert r["dual_use_count"] == 1            # psexec
    assert r["findings"][0]["exe"] == "MIMIKATZ.EXE"
    sev = {f["exe"]: f["severity"] for f in r["findings"]}
    assert sev["CMD.EXE"] == "INFO" and sev["WHOAMI.EXE"] == "INFO"
    assert sev["CHROME.EXE"] == "LOW"
    assert "RECENT_DUAL_USE" in next(f for f in r["findings"] if f["exe"] == "PSEXEC.EXE")["flags"]


def test_scan_prefetch_missing_dir(tmp_path):
    r = w.scan_prefetch(str(tmp_path / "nope"))
    assert r["accessible"] is False


# ---------------------------------------------------------------- event logs

def test_empty_unused_logs_not_flagged(tmp_path):
    d = tmp_path / "Logs"
    # Hundreds of never-used logs are exactly 68 KB; they must not be flagged.
    for i in range(50):
        _touch(str(d / f"Microsoft-Windows-Thing{i}%4Operational.evtx"), EMPTY)
    _touch(str(d / "Security.evtx"), 20 * 1024 * 1024)
    _touch(str(d / "System.evtx"), 2 * 1024 * 1024)
    _touch(str(d / "Application.evtx"), EMPTY)  # empty Application is unusual but not proof
    r = w.scan_event_logs(str(d), clearing={"available": True, "events": []})
    assert r["total"] == 53
    assert r["possibly_cleared"] == 0
    assert all(f["severity"] == "INFO" for f in r["findings"])
    assert len(r["findings"]) == 3   # only security-relevant logs are listed


def test_empty_security_log_flagged(tmp_path):
    d = tmp_path / "Logs"
    _touch(str(d / "Security.evtx"), EMPTY)
    _touch(str(d / "System.evtx"), 1024 * 1024)
    r = w.scan_event_logs(str(d), clearing={"available": True, "events": []})
    assert r["possibly_cleared"] == 1
    assert "EMPTY_BUSY_LOG" in r["findings"][0]["flags"]


def test_clear_events_reported(tmp_path):
    d = tmp_path / "Logs"
    _touch(str(d / "Security.evtx"), 5 * 1024 * 1024)
    xml = ("<Event><System><TimeCreated SystemTime='2026-11-20T03:14:15.000Z'/></System></Event>"
           "<Event><System><TimeCreated SystemTime=\"2026-11-21T04:00:00.000Z\"/></System></Event>")
    events = [{"channel": "Security", "event_id": 1102, "label": "cleared", "time": t}
              for t in w.parse_clear_events(xml)]
    assert len(events) == 2
    r = w.scan_event_logs(str(d), clearing={"available": True, "events": events})
    assert r["possibly_cleared"] == 2
    assert r["findings"][0]["flags"] == ["LOG_CLEARED"]


def test_wevtutil_unavailable_off_windows():
    if os.name != "nt":
        assert w.find_log_clearing() == {"available": False, "events": []}


# ---------------------------------------------------------------- hive copies

def test_hive_copies_found(tmp_path):
    temp = tmp_path / "WinTemp"
    users = tmp_path / "Users"
    _touch(str(temp / "sam.save"), 50_000)
    _touch(str(temp / "notes.txt"), 10)
    (users / "alice" / "AppData").mkdir(parents=True)
    _touch(str(users / "alice" / "Desktop" / "SYSTEM"), 12_000_000)
    _touch(str(users / "alice" / "Downloads" / "ntds.dit"), 30_000_000)
    hits = w.find_hive_copies([str(temp)], users_root=str(users))
    names = sorted(h["name"].lower() for h in hits)
    assert names == ["ntds.dit", "sam.save", "system"]


def test_hive_copies_none(tmp_path):
    (tmp_path / "Users").mkdir()
    assert w.find_hive_copies([str(tmp_path)], users_root=str(tmp_path / "Users")) == []


def test_amcache_is_informational(tmp_path):
    users = tmp_path / "Users"
    (users / "bob" / "AppData").mkdir(parents=True)
    _touch(str(users / "bob" / "NTUSER.DAT"), 1000, age_hours=0.1)
    r = w.scan_amcache_ntuser(str(users))
    assert all(f["severity"] == "INFO" for f in r["findings"])


# ---------------------------------------------------------------- rules file

def test_rules_tiers_do_not_overlap():
    pf = w.RULES["prefetch"]
    sets = [set(pf[k]["names"]) for k in ("offensive_tools", "dual_use_admin", "builtin_context")]
    assert not (sets[0] & sets[1]) and not (sets[0] & sets[2]) and not (sets[1] & sets[2])


# ---------------------------------------------------------------- dashboard protections

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(w, "BOUND_PORT", 5900)
    monkeypatch.setattr(w, "run_full_scan", lambda: {"ok": True})
    w.app.config["TESTING"] = True
    return w.app.test_client()


HOST = {"Host": "127.0.0.1:5900"}


def test_index_requires_token(client):
    assert client.get("/", headers=HOST).status_code == 403
    assert client.get("/?t=wrong", headers=HOST).status_code == 403


def test_index_with_token_sets_cookie_and_csp(client):
    r = client.get(f"/?t={w.SESSION_TOKEN}", headers=HOST)
    assert r.status_code == 200
    cookie = r.headers.get("Set-Cookie", "")
    assert w.COOKIE_NAME in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'nonce-" in csp and "frame-ancestors 'none'" in csp
    html = r.get_data(as_text=True)
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'<script nonce="{nonce}">' in html
    assert "onclick=" not in html           # no inline handlers (CSP-safe)


def test_dns_rebinding_host_rejected(client):
    r = client.get(f"/?t={w.SESSION_TOKEN}", headers={"Host": "evil.example:5900"})
    assert r.status_code == 403


def test_api_requires_cookie_and_header(client):
    assert client.get("/api/scan", headers=HOST).status_code == 403
    client.set_cookie(w.COOKIE_NAME, w.SESSION_TOKEN, domain="127.0.0.1")
    assert client.get("/api/scan", headers=HOST).status_code == 403   # missing X-WSTS
    r = client.get("/api/scan", headers={**HOST, "X-WSTS": "1"})
    assert r.status_code == 200 and r.get_json() == {"ok": True}


def test_quit_requires_cookie_and_header(client, monkeypatch):
    import threading
    started = []
    monkeypatch.setattr(threading, "Timer", lambda *a, **k: type("T", (), {"start": lambda self: started.append(1)})())
    assert client.post("/api/quit", headers=HOST).status_code == 403
    client.set_cookie(w.COOKIE_NAME, w.SESSION_TOKEN, domain="127.0.0.1")
    assert client.post("/api/quit", headers=HOST).status_code == 403
    r = client.post("/api/quit", headers={**HOST, "X-WSTS": "1"})
    assert r.status_code == 200 and started == [1]
