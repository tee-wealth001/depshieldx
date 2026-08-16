"""Smoke tests run in CI against a just-built depshieldx binary, before it's
uploaded as a release artifact -- see final-plan.md's "Smoke tests required
per platform build" list, which this implements directly: --help, a fast
scan, JSON output validity, receipt creation, host install, uninstall,
routing enable/disable, and a clear (non-crashing) response when Docker is
unavailable for --deep.

Deliberately plain Python (no shell-specific syntax) so the same script runs
unchanged on windows-latest/macos-13/macos-latest/ubuntu-latest.

Usage: python packaging/smoke_test.py <path-to-binary>
"""

import json
import subprocess
import sys

# Known depshieldx exit codes (depshieldx/cli/output.py) -- anything else
# from a real invocation means an unhandled crash, not a graceful outcome.
KNOWN_EXIT_CODES = {0, 10, 11, 12}


def _run(binary, args, timeout=120):
    return subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)


def _fail(message):
    print(f"FAIL: {message}")
    sys.exit(1)


def _check_help(binary):
    result = _run(binary, ["--help"])
    if result.returncode != 0:
        _fail(f"--help exited {result.returncode}: {result.stderr}")
    if "Usage:" not in result.stdout:
        _fail(f"--help output missing 'Usage:': {result.stdout!r}")
    print("OK: --help")


def _check_fast_scan_json(binary):
    result = _run(binary, ["scan", "requests", "--output", "json"])
    if result.returncode != 0:
        _fail(f"scan requests exited {result.returncode}: {result.stderr}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        _fail(f"scan requests --output json did not produce valid JSON: {exc}\nstdout: {result.stdout!r}")
    if payload.get("ecosystem") != "pypi":
        _fail(f"expected ecosystem 'pypi', got {payload.get('ecosystem')!r}")
    if not payload.get("resolution", {}).get("resolved_versions"):
        _fail("expected non-empty resolved_versions in scan JSON")
    print("OK: fast scan + JSON output validity")
    return payload


def _check_receipt_created(payload):
    receipt = payload.get("receipt") or {}
    if not receipt.get("receipt_id") and not receipt.get("receipts"):
        _fail(f"expected a receipt_id or receipts list in the scan report, got: {receipt}")
    print("OK: receipt creation")


def _check_install_and_uninstall(binary):
    # A tiny, harmless, pure-Python package -- safe to install/remove for real
    # on a disposable CI runner.
    result = _run(binary, ["install", "six", "--fast", "--output", "json"])
    if result.returncode != 0:
        _fail(f"install six exited {result.returncode}: {result.stderr}\nstdout: {result.stdout}")
    payload = json.loads(result.stdout)
    if not payload.get("install", {}).get("success"):
        _fail(f"install six did not report success: {payload.get('install')}")
    print("OK: host install")

    result = _run(binary, ["uninstall", "six"])
    if result.returncode != 0:
        _fail(f"uninstall six exited {result.returncode}: {result.stderr}\nstdout: {result.stdout}")
    print("OK: uninstall")


def _check_routing_enable_disable(binary):
    result = _run(binary, ["routing", "enable"])
    if result.returncode != 0:
        _fail(f"routing enable exited {result.returncode}: {result.stderr}")
    result = _run(binary, ["routing", "status"])
    if result.returncode != 0:
        _fail(f"routing status exited {result.returncode}: {result.stderr}")
    result = _run(binary, ["routing", "disable"])
    if result.returncode != 0:
        _fail(f"routing disable exited {result.returncode}: {result.stderr}")
    print("OK: routing enable/status/disable")


def _check_deep_does_not_crash(binary):
    # Docker/Trivy availability varies by CI platform -- the requirement is a
    # clear, known outcome (success, blocked, or "sandbox unavailable"), not
    # a raw Python traceback / unknown exit code.
    result = _run(binary, ["scan", "requests", "--deep", "--output", "json"], timeout=180)
    if result.returncode not in KNOWN_EXIT_CODES:
        _fail(
            f"--deep produced an unrecognized exit code {result.returncode} "
            f"(expected one of {sorted(KNOWN_EXIT_CODES)}): {result.stderr}"
        )
    try:
        json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        _fail(f"--deep --output json did not produce valid JSON even on a blocked/unavailable outcome: {exc}")
    print(f"OK: --deep exits cleanly (exit code {result.returncode}, valid JSON)")


def main():
    if len(sys.argv) != 2:
        print("usage: python packaging/smoke_test.py <path-to-binary>")
        sys.exit(2)
    binary = sys.argv[1]

    _check_help(binary)
    payload = _check_fast_scan_json(binary)
    _check_receipt_created(payload)
    _check_install_and_uninstall(binary)
    _check_routing_enable_disable(binary)
    _check_deep_does_not_crash(binary)

    print("All smoke tests passed.")


if __name__ == "__main__":
    main()
