import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.output import EXIT_OK
from depshieldx.sandbox import run_sandbox
from tests.fixture_packages import build_malicious_native_wheel, build_safe_native_wheel, build_safe_wheel


def _empty_advisories(*_args, **_kwargs):
    return {"hits": [], "warnings": [], "source": "fixture"}


def _copy_fixture_download(artifact_path: Path):
    def _copy(*_args, temp_dir=None, verbose=False):
        destination = Path(temp_dir if temp_dir is not None else _args[1])
        shutil.copy2(artifact_path, destination / artifact_path.name)

    return _copy


class FixturePackageIntegrationTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.check_provenance", return_value={"block": False, "warnings": [], "details": []})
    @patch(
        "depshieldx.scanner.fetch_all_sources_for_packages",
        return_value={
            "osv_results": {},
            "cisa_kev_results": {},
            "github_advisories": {"hits": [], "warnings": []},
            "deps_dev": {"hits": [], "warnings": []},
        },
    )
    def test_cli_fast_install_with_safe_fixture_wheel_uses_real_pip_install(
        self,
        _mock_sources,
        _mock_provenance,
    ):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wheel = build_safe_wheel(root, package_name="fixturepkg", version="1.0.0")
            install_root = root / "pip-target"
            install_root.mkdir()

            result = runner.invoke(
                cli,
                ["install", str(wheel), "--fast", "--output", "summary"],
                env={
                    **os.environ,
                    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                    "PIP_NO_WARN_SCRIPT_LOCATION": "1",
                    "PIP_TARGET": str(install_root),
                },
            )

            self.assertEqual(result.exit_code, EXIT_OK)
            self.assertTrue((install_root / "fixturepkg" / "__init__.py").exists())
            self.assertIn(
                "Host install: succeeded (fixturepkg==1.0.0, https://pypi.org/project/fixturepkg/1.0.0/)",
                result.output,
            )

    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(False, "docker offline"))
    def test_run_sandbox_with_safe_fixture_wheel_succeeds_on_local_backend(self, _mock_docker):
        with tempfile.TemporaryDirectory() as temp_dir:
            wheel = build_safe_native_wheel(temp_dir, package_name="fixturepkg", version="1.0.0")
            copy_download = _copy_fixture_download(wheel)

            with patch("depshieldx.sandbox.download_packages_local", side_effect=copy_download):
                result = run_sandbox(
                    ["fixturepkg==1.0.0"],
                    resolved_versions={"fixturepkg": "1.0.0"},
                    cache_enabled=False,
                    require_docker=False,
                )

        self.assertTrue(result.success)
        self.assertEqual(result.isolation["backend"], "local_subprocess")
        self.assertEqual(result.static_analysis["finding_count"], 0)
        self.assertEqual(result.evidence["imported_modules"], [])
        self.assertEqual(
            result.evidence["skipped_imports"],
            [{"module": "fixturepkg", "reason": "native_extension_distribution"}],
        )

    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(False, "docker offline"))
    def test_run_sandbox_blocks_malicious_fixture_wheel_before_install(self, _mock_docker):
        with tempfile.TemporaryDirectory() as temp_dir:
            wheel = build_malicious_native_wheel(temp_dir, package_name="badfixture", version="1.0.0")
            copy_download = _copy_fixture_download(wheel)

            with patch("depshieldx.sandbox.download_packages_local", side_effect=copy_download):
                result = run_sandbox(
                    ["badfixture==1.0.0"],
                    resolved_versions={"badfixture": "1.0.0"},
                    cache_enabled=False,
                    require_docker=False,
                )

        self.assertFalse(result.success)
        self.assertEqual(result.error_type, "static_analysis")
        finding_codes = [finding["code"] for finding in result.static_analysis["findings"]]
        self.assertIn("binary_network_exec_combo", finding_codes)

    def test_external_process_can_parse_scan_json_output(self):
        # Proves the JSON contract (final-plan.md Phase 0, definition of done #8): a
        # non-Python consumer -- here, a genuinely separate OS process, not an in-process
        # CliRunner invocation -- can run `depshieldx scan ... --output json` and parse
        # stdout directly as JSON, with no depshieldx internals available to it.
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
        self.assertEqual(payload["schema_version"], "1")
        self.assertEqual(payload["ecosystem"], "pypi")
        self.assertEqual(payload["package"], str(wheel))
        self.assertIn("resolution", payload)
        self.assertIn("decision", payload.get("receipt", {}) or {})
