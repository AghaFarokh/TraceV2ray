# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for TraceV2ray
#
# Build command: pyinstaller build.spec
# Output: dist/TraceV2ray.exe

block_cipher = None

a = Analysis(
    ['_entry.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'unittest', 'xmlrpc', 'pydoc', 'doctest',
        'ftplib', 'imaplib', 'smtplib', 'poplib',
        'turtle', 'turtledemo', 'test',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='TraceV2ray',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
