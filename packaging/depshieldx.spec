# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the depshieldx standalone binary.

Build with: pyinstaller packaging/depshieldx.spec

The two `datas` entries below are the exact, verified-working destinations
for resource_path() (depshieldx/core/runtime.py) to find them at runtime: its
frozen branch treats sys._MEIPASS as if it *were* the depshieldx/ package
directory, matching its non-frozen branch (base = the depshieldx/ package
directory). Bundling either file one level too deep (e.g.
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
        (os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "sandbox_wrapper.py"), "security/sandbox"),
        (os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "sandbox_wrapper_npm.js"), "security/sandbox"),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "docker", "npm_sandbox.Dockerfile"),
            "security/sandbox/docker",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "docker", "cargo_sandbox.Dockerfile"),
            "security/sandbox/docker",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "sandbox_wrapper_cargo.py"),
            "security/sandbox",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "docker", "go_sandbox.Dockerfile"),
            "security/sandbox/docker",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "sandbox_wrapper_go.py"),
            "security/sandbox",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "docker", "maven_sandbox.Dockerfile"),
            "security/sandbox/docker",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "sandbox_wrapper_maven.py"),
            "security/sandbox",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "docker", "nuget_sandbox.Dockerfile"),
            "security/sandbox/docker",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "sandbox_wrapper_nuget.py"),
            "security/sandbox",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "docker", "pub_sandbox.Dockerfile"),
            "security/sandbox/docker",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "sandbox_wrapper_pub.py"),
            "security/sandbox",
        ),
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
