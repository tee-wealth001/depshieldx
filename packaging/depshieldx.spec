# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the depshieldx standalone binary.

Build with: pyinstaller packaging/depshieldx.spec

The two `datas` entries below are the exact, verified-working destinations
for resource_path() (depshieldx/runtime.py) to find them at runtime: its
frozen branch treats sys._MEIPASS as if it *were* the depshieldx/ package
directory, matching its non-frozen branch (base = Path(__file__).parent,
i.e. depshieldx/ itself). Bundling either file one level too deep (e.g.
under an extra "depshieldx/" prefix) reproduces a real FileNotFoundError in
`depshieldx ui` -- caught and fixed during development, not theoretical.
"""

import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(SPEC)))

a = Analysis(
    [os.path.join(REPO_ROOT, "packaging", "entry.py")],
    pathex=[REPO_ROOT],
    binaries=[],
    datas=[
        (os.path.join(REPO_ROOT, "depshieldx", "sandbox_wrapper.py"), "."),
        (os.path.join(REPO_ROOT, "depshieldx", "sandbox_wrapper_npm.js"), "."),
        (
            os.path.join(REPO_ROOT, "depshieldx", "presentation", "web", "templates", "dashboard.html"),
            "presentation/web/templates",
        ),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="depshieldx",
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
)
