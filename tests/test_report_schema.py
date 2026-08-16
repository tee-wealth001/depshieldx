import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from tests.fixture_packages import build_safe_wheel

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "report.schema.json"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "reports"


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


class ReportSchemaTests(unittest.TestCase):
    def test_schema_itself_is_well_formed(self):
        Draft202012Validator.check_schema(_load_schema())

    def test_golden_fixture_scan_not_blocked_matches_schema(self):
        payload = json.loads((FIXTURES_DIR / "scan_not_blocked.json").read_text(encoding="utf-8"))
        Draft202012Validator(_load_schema()).validate(payload)

    def test_golden_fixture_scan_blocked_matches_schema(self):
        payload = json.loads((FIXTURES_DIR / "scan_blocked.json").read_text(encoding="utf-8"))
        Draft202012Validator(_load_schema()).validate(payload)

    def test_live_scan_report_matches_schema(self):
        # Strongest drift check: run the real CLI and validate what it actually produces
        # today, not just the golden fixtures captured at one point in time.
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wheel = build_safe_wheel(root, package_name="fixturepkg", version="1.0.0")

            completed = subprocess.run(
                [sys.executable, "-m", "depshieldx.cli", "scan", str(wheel), "--fast", "--output", "json"],
                capture_output=True,
                text=True,
                timeout=60,
                env={
                    **os.environ,
                    "DEPSHIELDX_CACHE_DIR": str(root / "cache"),
                    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                },
            )

        payload = json.loads(completed.stdout)
        Draft202012Validator(_load_schema()).validate(payload)


if __name__ == "__main__":
    unittest.main()
