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

from PyInstaller.utils.hooks import collect_data_files

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(SPEC)))

# sigstore._store bundles the real Sigstore/sigstage TUF trust-root JSON
# files (root.json/signing_config.v0.2.json/trusted_root.json) that
# sigstore._utils reads via `importlib.resources.files("sigstore._store")`
# -- a dynamic, string-based lookup PyInstaller's static import analysis
# can't trace. Confirmed directly this makes a real frozen build raise
# "No module named 'sigstore._store'" the moment any PyPI attestation
# verification is actually attempted (not just "unavailable" -- a real,
# confirmed-directly false-positive HARD BLOCK: the verification_failure
# signal from a missing module is otherwise indistinguishable from a
# genuine cryptographic failure), and confirmed directly this specific
# fix -- collect_data_files scoped to "sigstore._store" with
# include_py_files=True, so the package's own __init__.py lands on disk
# at sys._MEIPASS alongside its real JSON data siblings, all from the
# same real filesystem location -- resolves it end to end in a real
# frozen build (verified attestations succeed again, no error).
SIGSTORE_STORE_DATAS = collect_data_files("sigstore._store", include_py_files=True)

a = Analysis(
    [os.path.join(REPO_ROOT, "packaging", "entry.py")],
    pathex=[REPO_ROOT],
    binaries=[],
    datas=SIGSTORE_STORE_DATAS + [
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
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "docker", "rubygems_sandbox.Dockerfile"),
            "security/sandbox/docker",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "sandbox_wrapper_rubygems.py"),
            "security/sandbox",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "docker", "composer_sandbox.Dockerfile"),
            "security/sandbox/docker",
        ),
        (
            os.path.join(REPO_ROOT, "depshieldx", "security", "sandbox", "sandbox_wrapper_composer.py"),
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
