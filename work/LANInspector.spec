# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['outputs/LAN-Inspector/lan_inspector.py'],
    pathex=[],
    binaries=[],
    datas=[('outputs/LAN-Inspector/mac-vendors.csv', '.'), ('outputs/LAN-Inspector/mac-vendors-source.json', '.'), ('outputs/LAN-Inspector/local_ports.ps1', '.')],
    hiddenimports=[],
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
    [],
    exclude_binaries=True,
    name='LANInspector',
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
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='LANInspector',
)

