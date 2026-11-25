# -*- mode: python ; coding: utf-8 -*-
# ── WSTS — Windows Security Threat Scanner — PyInstaller spec ────────────────
# Packages win_scanner_app.py (Flask local dashboard) as a FOLDER build
# (dist\WSTS\WSTS.exe + dist\WSTS\_internal\...), which the Inno Setup script
# (wsts.iss) then wraps into WSTS-Setup-<version>.exe.
#
#   pyinstaller wsts.spec --clean --noconfirm
#
# Why a folder build instead of --onefile:
#   • A one-file build unpacks itself into %TEMP% and runs from there on every
#     launch, which is exactly how malware droppers behave. Machine-learning
#     AV engines (e.g. Deep Instinct) score that pattern heavily.
#   • The folder build runs in place from Program Files, starts faster, and
#     every file can be signed and inspected.
#
# Other AV-friendliness choices:
#   • upx=False: packed binaries are a top cause of false positives.
#   • Detection rules ship as wsts_rules.json, not as strings inside the EXE.
#   • uac_admin=True: Prefetch and event logs need admin rights; asking up
#     front beats silently showing "Permission denied".
#   • Signing happens post-build in build_wsts.ps1 (Artifact Signing), so no
#     certificate material lives in the repo.

import os

PROJECT_DIR = os.path.abspath(SPECPATH)  # noqa: F821 (SPECPATH injected by PyInstaller)

a = Analysis(
    [os.path.join(PROJECT_DIR, 'win_scanner_app.py')],
    pathex=[PROJECT_DIR],
    binaries=[],
    datas=[
        (os.path.join(PROJECT_DIR, 'static', 'img', 'wsts_shield.png'), 'static/img'),
        (os.path.join(PROJECT_DIR, 'wsts_rules.json'), '.'),
    ],
    hiddenimports=['jinja2', 'werkzeug', 'click', 'itsdangerous'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'PyQt5', 'PySide2', 'PySide6', 'matplotlib', 'numpy',
              'pandas', 'pytest'],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,        # folder build: binaries go to COLLECT below
    name='WSTS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=os.path.join(PROJECT_DIR, 'static', 'img', 'wsts.ico'),
    version=os.path.join(PROJECT_DIR, 'version_wsts.txt'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='WSTS',
)
