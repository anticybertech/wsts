# WinCyberScan™ / Windows Security Threat Scanner (WSTS)

**A free, read-only forensic scanner for Windows.**
WSTS inspects your PC for malware indicators, persistence mechanisms, and signs
of log or credential-store tampering — then shows the results in your browser.
It runs **100% on your machine**. Nothing is uploaded, and no account is required.

Website: **https://wincyberscan.com**

---

## What WSTS does

WSTS examines the same forensic artifacts that incident responders review after a suspected compromise. It **only reads** these artifacts — it never changes, deletes, quarantines, or transmits anything.

Check what it tells you.

**Prefetch execution**: Whether known attack tools (Mimikatz, Rubeus, Cobalt Strike…) or commonly abused admin tools (PsExec, certutil, ntdsutil, rclone…) have run on this PC.

**Startup persistence**: Suspicious scripts or shortcuts planted in Startup folders that would re-launch malware on every boot.

**Event-log tampering**: Log-clearing events (Security 1102, System 104) in the last 30 days, and an empty Security or System log — common ways attackers hide their tracks.

**Credential stores**: Exported copies of the SAM, SYSTEM or SECURITY hives (or `ntds.dit`) left in Temp, Public, Desktop, Downloads and similar folders — a classic step in offline password-hash theft.

**Amcache & NTUSER**: Status of the hives that record application-execution history (informational).

Each finding is tagged so you can tell routine activity from things worth a closer look (for example: `KNOWN_OFFENSIVE_TOOL`, `DUAL_USE_TOOL`, `LOG_CLEARED`, `HIVE_COPY_OUTSIDE_CONFIG`, `SUSPICIOUS_LNK_TARGET`). Detection rules live in [`wsts_rules.json`](wsts_rules.json).

---

## Before you download — make sure it's safe

Security tools are often flagged by antivirus because they read the same files
malware does. To remove all doubt, every WSTS release is fully verifiable.

1. **Download only from** `https://wincyberscan.com`. We never publish WSTS on
   third-party download sites.
2. **Check the SHA-256 hash.** The official hash is shown on the download page.
   Compare it against your downloaded file (see "Verify your download" below).
3. **Confirm the digital signature.** Releases are signed as
   *Antibody Cyber Technology, LLC*.
4. **Review the VirusTotal report.** The download page links to a multi-engine
   scan of the exact file you're getting.

> If the hash on your file does **not** match the one on the website, delete the
> file and download it again. Do not run a file whose hash doesn't match.

---

## Installing & running

1. Go to **https://wincyberscan.com** and click **Download for Windows**.
2. Verify the file (see [Verify download](https://wincyberscan.com/#verify)) — recommended.
3. Run **`WSTS-Setup-<version>.exe`** and follow the installer. It installs to *Program Files\Antibody Cyber\WSTS* and adds Start-menu shortcuts and an uninstaller.
4. Start **WSTS** from the Start menu and approve the Administrator prompt. Admin rights let WSTS read Prefetch and the event logs; without them the scan still runs, but those areas show as *inaccessible*.
5. WSTS opens its dashboard in your default browser at **`http://127.0.0.1:5900`** (or another free port if 5900 is taken). The dashboard only accepts the browser session WSTS opened for you.

**If Windows SmartScreen warns you,** that's expected with newer security tools. After you've verified the SHA-256 hash, click **More info → Run anyway**.

---

## Using the dashboard

1. Click **Scan Now**. The scan takes a few seconds.
2. Results are grouped into collapsible sections: Prefetch, Startup, Event Logs, Credential Stores, and Amcache/NTUSER.
3. Click any section header to expand or collapse it.
4. The summary row at the top shows the host name, scan time, and a count of flagged items.

### Reading the results

- **Green/informational** items are normal.
- **Flagged** items carry one or more tags explaining *why* they were flagged.
- **HIGH** means a strong indicator (a known attack tool ran, logs were cleared, a credential hive was exported). **MEDIUM** means a legitimate admin tool that attackers often abuse — confirm you or your IT staff ran it.
- Built-in tools like PowerShell or `cmd` are listed as **INFO** for context only; they run on every PC.

### What to do with a flagged item

1. Note the **path**, **timestamp**, and **tags**.
2. Ask: *Do I recognize this program, and did I expect it to run at that time?*
3. If something looks genuinely unexpected — for example, a hacking tool you never installed, or a Security log that was recently cleared — treat the machine as potentially compromised: disconnect it from the network and consult an incident-response professional.

---

## Verify your download

Open **PowerShell** in the folder where you saved the file and run:

```powershell
# 1. Check the SHA-256 hash (compare to the value on the website)
Get-FileHash .\WSTS-Setup-1.0.1.exe -Algorithm SHA256

# 2. Confirm the digital signature is valid
Get-AuthenticodeSignature .\WSTS-Setup-1.0.1.exe | Format-List Status, SignerCertificate
```

- The hash from step 1 must **exactly** match the one shown on
  https://wincyberscan.com.
- Step 2 should report **Status: Valid** and a publisher of
  **Antibody Cyber Technology, LLC**.

---

## Privacy

- WSTS makes **no outbound network connections**. Its dashboard listens only on `127.0.0.1` (this PC), protected by a per-launch session token. You can block it in your firewall, and it will still work.
- All scanning happens locally. **No results, files, or telemetry leave your machine.**
- No account, no registration, no email address required.

---

## Frequently asked questions

**Does WSTS remove malware?**
No. WSTS is a *detection and assessment* tool. It reports indicators so you can
investigate; it does not delete or quarantine anything.

**Will it change anything on my system?**
No. It is strictly read-only.

**Do I have to install it?**
Yes, from version 1.0.1 WSTS ships as a standard signed installer, and you can
remove it any time from *Settings → Apps*. (Version 1.0.0 was a single
executable.)

**Why does it need administrator rights?**
Some Windows logs and registry hives are protected. Administrator access lets
WSTS read them. Running without admin still works, but those areas are skipped.

**Which Windows versions are supported?**
Windows 10 and Windows 11 (64-bit).

**How do I close it?**
Click **Quit** in the top-right corner of the dashboard, then close the tab.

---

## Building from source

```powershell
pip install -r requirements.txt
python -m pytest -q                 # tests run on any OS
python win_scanner_app.py           # dev run (Windows)

# Release build (Windows): PyInstaller folder build + Inno Setup installer,
# signed with Microsoft Artifact Signing.
winget install -e --id Microsoft.Azure.ArtifactSigningClientTools
winget install -e --id JRSoftware.InnoSetup
az login
.\build_wsts.ps1 -Version 1.0.1 -CertProfile <certificate-profile-name>
```

See [CHANGELOG.md](CHANGELOG.md) for what changed in each release.

---

## Support

Questions or to report a security issue: wayne@antibodynet.net
Source code: https://github.com/anticybertech/wsts

© 2026 Antibody Cyber Technology, LLC
