import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from depshieldx.resolver import (
    ResolutionResult,
    _build_install_target,
    _build_resolution_result,
    _load_pip_report,
    resolve_dependencies,
)


class ResolverTests(unittest.TestCase):
    def test_load_pip_report_accepts_utf8_bom(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"
            report_path.write_text('{"install": []}', encoding="utf-8-sig")

            report = _load_pip_report(report_path)

        self.assertEqual(report, {"install": []})

    def test_build_install_target_uses_canonical_name_and_version(self):
        report = {
            "install": [
                {"metadata": {"name": "Flask", "version": "3.1.3"}},
                {"metadata": {"name": "Werkzeug", "version": "3.1.7"}},
            ]
        }

        target = _build_install_target("flask", report)

        self.assertEqual(target, "Flask==3.1.3")

    def test_build_install_target_uses_metadata_for_direct_wheel_reference(self):
        report = {
            "install": [
                {"metadata": {"name": "fixturepkg", "version": "1.0.0"}, "is_direct": True},
            ]
        }

        target = _build_install_target("/tmp/fixturepkg-1.0.0-py3-none-any.whl", report)

        self.assertEqual(target, "fixturepkg==1.0.0")

    def test_build_resolution_result_records_selected_artifacts(self):
        report = {
            "install": [
                {
                    "metadata": {"name": "Flask", "version": "3.1.3"},
                    "download_info": {
                        "url": "https://files.pythonhosted.org/packages/x/Flask-3.1.3-py3-none-any.whl",
                        "archive_info": {"hashes": {"sha256": "abc123"}},
                    },
                }
            ]
        }

        result = _build_resolution_result(
            report,
            install_target="flask",
            fallback_packages=["flask"],
            install_args=["flask"],
            requested_targets=["flask"],
            source_type="package",
        )

        self.assertEqual(result.selected_artifacts["Flask"][0]["filename"], "Flask-3.1.3-py3-none-any.whl")
        self.assertEqual(result.selected_artifacts["Flask"][0]["digests"]["sha256"], "abc123")

    @patch("depshieldx.resolver.subprocess.run")
    def test_resolve_dependencies_uses_current_python_executable(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, [sys.executable], stderr="ERROR: test failure")

        resolve_dependencies("flask")

        self.assertEqual(mock_run.call_args.args[0][0], sys.executable)

    @patch(
        "depshieldx.resolver.subprocess.run",
        side_effect=subprocess.CalledProcessError(
            1,
            ["pip"],
            stderr="ERROR: No matching distribution found for flask",
        ),
    )
    def test_resolve_dependencies_falls_back_on_pip_failure(self, _mock_run):
        result = resolve_dependencies("flask")

        self.assertEqual(
            result,
            ResolutionResult(
                packages=[],
                install_target="flask",
                resolved_versions={},
                install_args=["flask"],
                requested_targets=["flask"],
                resolution_succeeded=False,
                resolution_error="ERROR: No matching distribution found for flask",
            ),
        )
