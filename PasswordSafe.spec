# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path

# In a .spec file, __file__ is not defined. Use the CWD PyInstaller runs from.
REPO_ROOT = Path.cwd()

ICON_PATH = REPO_ROOT / "assets" / "app.ico"
ICON_ARG = str(ICON_PATH) if ICON_PATH.exists() else None

a = Analysis(
    ['main.py'],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=[
        ('icon-safe.png', '.'),   # keep if you load this at runtime
        # ('assets\\app.ico', 'assets'),  # only if you read it at runtime
    ],
    hiddenimports=[
        'storage', 'login_dialog', 'main_window', 'settings', 'dashboard'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PasswordSafe',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                 # set True only if UPX is installed
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,             # set True temporarily to see tracebacks
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON_ARG,
)
