import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import ANY, Mock, patch
import subprocess
import sys

from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.engine import (
    _finalize_routing_after_install,
    _handle_routing_choice,
    _run_cli_command,
    _run_fast_checks,
)
from depshieldx.cli.output import (
    EXIT_BLOCKED,
    EXIT_OK,
    _determine_exit_code,
    _format_summary,
    _render_report,
    _summary_line_color,
)
from depshieldx.cli.prerequisites import _runtime_environment_report
from depshieldx.receipts import ReceiptUnavailableError
from depshieldx.resolver import ResolutionResult
from depshieldx.routing import should_prompt_for_routing
from depshieldx.sandbox import SandboxResult


class FormatSummaryTests(unittest.TestCase):
    def test_runtime_environment_report_blocks_old_pip(self):
        with patch("depshieldx.cli.prerequisites.sys.version_info", (3, 11, 4, "final", 0)):
            with patch("depshieldx.cli.prerequisites.metadata.version", return_value="25.2"):
                report = _runtime_environment_report()

        self.assertTrue(report["block"])
        self.assertIn("requires pip>=25.3", report["reason"])

    def test_runtime_environment_report_accepts_secure_python_and_pip(self):
        with patch("depshieldx.cli.prerequisites.sys.version_info", (3, 11, 4, "final", 0)):
            with patch("depshieldx.cli.prerequisites.metadata.version", return_value="25.3"):
                report = _runtime_environment_report()

        self.assertFalse(report["block"])
        self.assertTrue(report["python"]["ok"])
        self.assertTrue(report["pip"]["ok"])

    def test_summary_line_color_marks_host_install_success_and_failure(self):
        self.assertEqual(
            _summary_line_color("Host install: succeeded (fastapi==0.135.2, https://pypi.org/project/fastapi/0.135.2/)"),
            "green",
        )
        self.assertEqual(_summary_line_color("Host install: failed"), "red")
        self.assertEqual(_summary_line_color("Host install: blocked (policy)"), "red")
        self.assertEqual(_summary_line_color("Runtime prerequisites: satisfied"), "green")
        self.assertEqual(_summary_line_color("Runtime prerequisites: blocked (requires pip>=25.3)"), "red")

    def test_summary_line_color_uses_warning_and_info_severity(self):
        self.assertEqual(_summary_line_color("Scan verdict: passed with 1 warning(s), 0 info item(s)"), "yellow")
        self.assertEqual(_summary_line_color("Provenance verdict: passed with 0 warning(s), 2 info item(s)"), "blue")
        self.assertEqual(_summary_line_color("Scan verdict: passed with 0 warning(s), 0 info item(s)"), "green")
        self.assertEqual(_summary_line_color("Policy verdict: passed with 1 warning(s), 0 info item(s)"), "yellow")
        self.assertEqual(_summary_line_color("Receipts: allowed (1 package receipt)"), "blue")
        self.assertEqual(_summary_line_color("Receipt ID: abc123"), "blue")
        self.assertEqual(_summary_line_color("PyPI project links: Flask==3.1.3 (https://pypi.org/project/Flask/3.1.3/)"), "blue")
        self.assertEqual(_summary_line_color("  - Flask==3.1.3 (https://pypi.org/project/Flask/3.1.3/)"), "blue")

    def test_render_report_summary_mode_omits_json_report(self):
        report = {
            "package": "flask",
            "mode": "fast",
            "resolution": {"requested_targets": ["flask"], "resolved_versions": {"Flask": "3.1.3"}},
            "install": {"success": True, "target": "Flask==3.1.3"},
        }

        rendered = _render_report(report, "summary")

        self.assertTrue(rendered.startswith("Summary\nPackage: flask"))
        self.assertNotIn("\n\nReport\n{", rendered)

    def test_format_summary_uses_clear_historical_wording_for_osv(self):
        report = {
            "package": "demo",
            "mode": "fast",
            "resolution": {"packages": ["demo"]},
            "scan": {
                "block": False,
                "warnings": [],
                "infos": [],
                "threat_intelligence": {
                    "multi_source_cves": {
                        "demo": {
                            "current": [],
                            "historical": [{"source": "osv", "cve_id": "CVE-2024-0001"}],
                        }
                    },
                    "github_advisories": {"hits": [], "warnings": []},
                    "deps_dev": {"hits": [], "warnings": []},
                    "sources": [],
                    "hits": [],
                },
            },
        }

        summary = _format_summary(report)

        self.assertIn("  • osv: 0 affecting resolved version(s), 1 historical/fixed entry in resolved dependency history", summary)

    def test_format_summary_includes_key_verdicts(self):
        report = {
            "package": "flask",
            "mode": "deep",
            "risk": {
                "score": 14,
                "level": "medium",
                "reasons": [{"points": 10, "code": "differential_medium", "message": "1 medium differential finding(s) present"}],
            },
            "resolution": {
                "packages": ["Flask", "Werkzeug"],
                "requested_targets": ["flask"],
                "resolved_versions": {"Flask": "3.1.3", "Werkzeug": "3.1.7"},
            },
            "provenance": {
                "block": False,
                "warnings": [],
                "infos": ["Flask==3.1.3: resolved release is source-only"],
                "details": [
                    {
                        "package": "Flask",
                        "version": "3.1.3",
                        "signals": {
                            "attested_file_count": 2,
                            "verified_attestation_file_count": 1,
                            "attestation_verification_available": True,
                            "verification_failure": {
                                "filename": "Flask-3.1.3-py3-none-any.whl",
                                "error": "subject does not match distribution digest",
                            },
                            "verification_unavailable": {
                                "filename": "Werkzeug-3.1.7-py3-none-any.whl",
                                "error": "Failed to refresh TUF metadata",
                            },
                        },
                    }
                ],
            },
            "differential": {
                "available": True,
                "baseline_version": "3.1.2",
                "added_files_count": 4,
                "findings": [
                    {
                        "severity": "medium",
                        "code": "new_static_findings",
                        "message": "The candidate version introduced new static-analysis findings.",
                    }
                ],
            },
            "policy": {"block": False, "violations": []},
            "scan": {
                "block": False,
                "warnings": [],
                "infos": ["flask reputation: package is very new"],
                "threat_intelligence": {
                    "hits": [{"package": "flask"}],
                    "sources": ["feed.json"],
                    "osv": {"hits": [{"package": "flask"}]},
                    "github_advisories": {"hits": [{"package": "flask"}]},
                    "cisa_kev": {"hits": []},
                    "deps_dev": {"hits": [{"package": "flask"}]},
                },
            },
            "sandbox": {
                "success": True,
                "isolation": {"backend": "docker"},
                "trust": {"level": "high", "warnings": [], "infos": []},
                "cache": {"hit": True, "fingerprint": "abc123"},
                "bundle": {
                    "downloaded_files": ["Flask-3.1.3.whl", "Werkzeug-3.1.7.whl"],
                    "artifact_hashes": {
                        "Flask-3.1.3.whl": "abc",
                        "Werkzeug-3.1.7.whl": "def",
                    },
                },
                "static_analysis": {
                    "finding_count": 1,
                    "high_count": 0,
                    "medium_count": 1,
                    "blocked": False,
                    "findings": [{"code": "payload_obfuscation", "file": "pkg/module.py"}],
                },
                "evidence": {
                    "write_count": 12,
                    "syscall_counts": {
                        "filesystem_mutation": 4,
                        "process_exec": 1,
                        "network": 0,
                    },
                    "allowed_subprocesses": [["uname", "-rs"]],
                    "blocked_events": [],
                    "imported_modules": ["flask"],
                    "skipped_imports": [{"module": "markupsafe", "reason": "native_extension_distribution"}],
                    "import_failures": [
                        {
                            "module": "flask",
                            "type": "ImportError",
                            "message": "cannot import name 'X' from 'werkzeug'",
                        }
                    ],
                    "verdicts": [
                        {"severity": "info", "code": "runtime_probes_allowed"},
                        {"severity": "info", "code": "entrypoint_scripts_created"},
                        {"severity": "info", "code": "post_install_import_checks_run"},
                    ],
                },
            },
            "install": {"success": True, "target": "Flask==3.1.3", "source": "offline_host_bundle"},
            "receipt": {"decision": "allowed", "receipt_id": "abc123", "path": "/tmp/receipt.json"},
        }

        summary = _format_summary(report)

        self.assertIn("Package: flask", summary)
        self.assertIn("Mode: deep", summary)
        self.assertIn("Risk: medium (14/100)", summary)
        self.assertIn("Top risk reason: 1 medium differential finding(s) present", summary)
        self.assertIn("Resolved packages: 2", summary)
        self.assertIn("Scan verdict: passed with 0 warning(s), 1 info item(s)", summary)
        self.assertIn("Threat intelligence: 1 custom feed hit(s)", summary)
        self.assertIn("CVE sources across all resolved packages:", summary)
        self.assertIn("  • github-advisories: 1 affecting resolved version(s)", summary)
        self.assertIn("  • deps-dev: 0 advisories, 1 package record(s) checked", summary)
        self.assertIn("Feed sources: 1 custom source(s)", summary)
        self.assertIn("Provenance verdict: passed with 0 warning(s), 1 info item(s)", summary)
        self.assertIn("Attestation verification: 1/2 attested file(s) verified, available", summary)
        self.assertIn(
            "First attestation failure: Flask-3.1.3-py3-none-any.whl (subject does not match distribution digest)",
            summary,
        )
        self.assertIn(
            "Attestation infrastructure issue: Werkzeug-3.1.7-py3-none-any.whl (Failed to refresh TUF metadata)",
            summary,
        )
        self.assertIn("Differential analysis: baseline 3.1.2, 1 finding(s), 4 added file(s)", summary)
        self.assertIn("First differential finding: new_static_findings", summary)
        self.assertIn("Policy verdict: passed with 0 warning(s), 0 info item(s)", summary)
        self.assertIn("Sandbox verdict: passed", summary)
        self.assertIn("Sandbox backend: docker", summary)
        self.assertIn("Sandbox trust: high", summary)
        self.assertIn("Bundle cache: hit", summary)
        self.assertIn("Locked bundle: 2 artifact(s), 2 hash(es)", summary)
        self.assertIn("Static analysis: 1 finding(s), 0 high, 1 medium", summary)
        self.assertIn("Sandbox evidence: 12 writes, 1 allowed subprocess probe(s), 0 blocked event(s)", summary)
        self.assertIn("Syscall trace: 4 filesystem, 1 process, 0 network", summary)
        self.assertIn("Import checks: 1 imported, 1 skipped, 1 failed", summary)
        self.assertIn("Behavioral verdicts: 0 high, 0 medium, 3 info", summary)
        self.assertIn(
            "First import failure: flask (ImportError: cannot import name 'X' from 'werkzeug')",
            summary,
        )
        self.assertIn(
            "Host install: succeeded (Flask==3.1.3, https://pypi.org/project/Flask/3.1.3/, source=offline_host_bundle)",
            summary,
        )
        self.assertIn("Receipts: allowed (1 package receipt)", summary)
        self.assertIn("Receipt ID: abc123", summary)
        self.assertIn("Receipt path:", summary)
        self.assertIn("  - /tmp/receipt.json", summary)

    def test_format_summary_includes_multiple_requested_project_links(self):
        report = {
            "package": "flask, requests",
            "mode": "fast",
            "resolution": {
                "packages": ["Flask", "requests"],
                "requested_targets": ["flask", "requests"],
                "resolved_versions": {"Flask": "3.1.3", "requests": "2.33.0"},
            },
            "install": {"success": True, "target": "flask, requests"},
        }

        summary = _format_summary(report)

        self.assertIn("Host install: succeeded (flask, requests)", summary)
        self.assertIn("PyPI project links:", summary)
        self.assertIn(
            "  - Flask==3.1.3 (https://pypi.org/project/Flask/3.1.3/)",
            summary,
        )
        self.assertIn(
            "  - requests==2.33.0 (https://pypi.org/project/requests/2.33.0/)",
            summary,
        )

    def test_format_summary_includes_runtime_prerequisites(self):
        report = {
            "package": "demo",
            "mode": "fast",
            "environment": {
                "block": True,
                "reason": "requires pip>=25.3 because depshieldx shells out to the local pip (running 25.2)",
                "python": {"version": "3.11.4", "required": "Python>=3.11.4", "ok": True},
                "pip": {"version": "25.2", "required": "pip>=25.3", "ok": False, "error": None},
            },
            "install": {"blocked": True, "reason": "environment"},
        }

        summary = _format_summary(report)

        self.assertIn("Runtime prerequisites: blocked", summary)
        self.assertIn("Python runtime: 3.11.4 (need Python>=3.11.4)", summary)
        self.assertIn("pip runtime: 25.2 (need pip>=25.3)", summary)

    def test_format_summary_includes_requested_package_breakdown_for_multi_package_scan(self):
        report = {
            "package": "langchain, requests",
            "mode": "deep",
            "resolution": {
                "packages": ["langchain", "requests", "httpx"],
                "requested_targets": ["langchain", "requests"],
                "resolved_versions": {"langchain": "1.2.13", "requests": "2.33.1", "httpx": "0.28.1"},
            },
            "scan": {
                "block": False,
                "warnings": [],
                "infos": [],
                "threat_intelligence": {
                    "multi_source_cves": {
                        "langchain": {"current": [], "historical": [{"source": "osv", "cve_id": "CVE-2024-0001"}]},
                        "requests": {"current": [], "historical": []},
                        "httpx": {"current": [], "historical": [{"source": "osv", "cve_id": "CVE-2024-0002"}]},
                    },
                    "github_advisories": {"hits": [], "warnings": []},
                    "deps_dev": {
                        "hits": [
                            {"package": "langchain", "advisory_count": 0},
                            {"package": "requests", "advisory_count": 0},
                            {"package": "httpx", "advisory_count": 0},
                        ],
                        "warnings": [],
                    },
                    "sources": [],
                    "hits": [],
                },
            },
        }

        summary = _format_summary(report)

        self.assertIn("Requested package breakdown:", summary)
        self.assertIn("  langchain==1.2.13:", summary)
        self.assertIn("    • osv: 0 affecting resolved version(s), 1 historical/fixed entry in resolved dependency history", summary)
        self.assertIn("    • deps-dev: 0 advisories, 1 package record(s) checked", summary)
        self.assertIn("  requests==2.33.1:", summary)

    def test_format_summary_shows_blocked_dependency_and_unverified_cisa_kev_matches(self):
        report = {
            "package": "beautifulsoup4, matplotlib",
            "mode": "fast",
            "resolution": {
                "packages": ["beautifulsoup4", "matplotlib", "six"],
                "requested_targets": ["beautifulsoup4", "matplotlib"],
                "resolved_versions": {
                    "beautifulsoup4": "4.14.3",
                    "matplotlib": "3.10.8",
                    "six": "1.17.0",
                },
            },
            "scan": {
                "block": True,
                "reason": "matplotlib==3.10.8 has GitHub advisory GHSA-demo",
                "blocked_package": "six",
                "blocked_version": "1.17.0",
                "blocked_source": "cisa-kev",
                "blocked_advisory_id": "CVE-2022-24112",
                "warnings": [],
                "infos": [],
                "threat_intelligence": {
                    "multi_source_cves": {
                        "beautifulsoup4": {"current": [], "historical": [], "unverified": []},
                        "matplotlib": {"current": [], "historical": [], "unverified": []},
                        "six": {
                            "current": [],
                            "historical": [],
                            "unverified": [{"source": "cisa-kev", "cve_id": "CVE-2022-24112"}],
                        },
                    },
                    "github_advisories": {"hits": [], "warnings": []},
                    "deps_dev": {
                        "hits": [
                            {"package": "beautifulsoup4", "advisory_count": 0},
                            {"package": "matplotlib", "advisory_count": 0},
                            {"package": "six", "advisory_count": 0},
                        ],
                        "warnings": [],
                    },
                    "cisa_kev": {
                        "hits": [],
                        "unverified_hits": [{"package": "six", "cve_id": "CVE-2022-24112"}],
                        "warnings": [],
                    },
                    "sources": [],
                    "hits": [],
                },
            },
        }

        summary = _format_summary(report)

        self.assertIn("Blocked dependency: six==1.17.0 (source=cisa-kev, CVE-2022-24112)", summary)
        self.assertIn("CVE sources across all resolved packages:", summary)
        self.assertIn("  • cisa-kev: 0 affecting resolved version(s), 1 unverified match(es)", summary)

    def test_format_summary_can_include_historical_cve_details(self):
        report = {
            "package": "langchain, requests",
            "mode": "deep",
            "resolution": {
                "packages": ["langchain", "requests"],
                "requested_targets": ["langchain", "requests"],
                "resolved_versions": {"langchain": "1.2.13", "requests": "2.33.1"},
            },
            "scan": {
                "block": False,
                "warnings": [],
                "infos": [],
                "threat_intelligence": {
                    "multi_source_cves": {
                        "langchain": {
                            "current": [],
                            "historical": [
                                {
                                    "source": "osv",
                                    "cve_id": "CVE-2024-0001",
                                    "affected_versions": ["<1.2.0"],
                                    "fixed_in_version": "1.2.0",
                                }
                            ],
                        },
                        "requests": {"current": [], "historical": []},
                    },
                    "github_advisories": {"hits": [], "warnings": []},
                    "deps_dev": {"hits": [], "warnings": []},
                    "sources": [],
                    "hits": [],
                },
            },
        }

        summary = _format_summary(report, include_historical_details=True)

        self.assertIn("Historical/fixed CVEs:", summary)
        self.assertIn("  langchain==1.2.13:", summary)
        self.assertIn("    - CVE-2024-0001 (<1.2.0; fixed in 1.2.0)", summary)

    def test_format_summary_includes_multi_package_receipt_paths(self):
        report = {
            "package": "langchain, requests",
            "mode": "deep",
            "receipt": {
                "decision": "allowed",
                "receipts": [
                    {
                        "package": "langchain",
                        "package_version": "1.2.13",
                        "path": "/tmp/langchain.json",
                    },
                    {
                        "package": "requests",
                        "package_version": "2.33.1",
                        "path": "/tmp/requests.json",
                    },
                ],
            },
        }

        summary = _format_summary(report)

        self.assertIn("Receipts: allowed (2 package receipts)", summary)
        self.assertIn("  - langchain==1.2.13: /tmp/langchain.json", summary)
        self.assertIn("  - requests==2.33.1: /tmp/requests.json", summary)

    def test_render_report_json_mode_omits_summary(self):
        report = {
            "package": "flask",
            "mode": "fast",
            "resolution": {"requested_targets": ["flask"], "resolved_versions": {"Flask": "3.1.3"}},
            "install": {"success": True, "target": "Flask==3.1.3"},
        }

        rendered = _render_report(report, "json")

        self.assertTrue(rendered.startswith("Report\n{"))
        self.assertNotIn("Summary", rendered)

    @patch("depshieldx.cli.report.write_receipt", side_effect=ReceiptUnavailableError("receipt store unavailable"))
    def test_render_report_summary_handles_receipt_unavailable(self, _mock_write_receipt):
        report = {
            "package": "flask",
            "mode": "fast",
            "install": {"success": True, "target": "Flask==3.1.3"},
        }

        rendered = _render_report(report, "summary")

        self.assertIn("Receipt: unavailable (receipt store unavailable)", rendered)

    def test_determine_exit_code_for_blocked_report(self):
        report = {"install": {"blocked": True, "reason": "policy"}}

        exit_code = _determine_exit_code(report)

        self.assertEqual(exit_code, EXIT_BLOCKED)

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    def test_cli_install_returns_blocked_exit_code(
        self,
        mock_resolve,
        mock_fast_checks,
    ):
        mock_resolve.return_value = ResolutionResult(
            packages=["flask"],
            install_target="Flask==3.1.3",
            resolved_versions={"Flask": "3.1.3"},
        )
        mock_fast_checks.return_value = (
            {"block": False, "warnings": [], "infos": [], "details": []},
            {"block": True, "reason": "bad package", "warnings": [], "infos": []},
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["install", "flask", "--fast", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_BLOCKED)
        self.assertIn("Summary", result.output)
        self.assertIn("Host install: blocked", result.output)
        self.assertNotIn("Report\n{", result.output)

    @patch("depshieldx.cli.engine.scan_vulnerabilities")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.check_provenance", side_effect=SystemExit(0))
    def test_run_fast_checks_converts_system_exit_into_blocked_provenance_result(
        self,
        _mock_provenance,
        mock_scan,
    ):
        mock_scan.return_value = {
            "block": False,
            "warnings": [],
            "infos": [],
            "threat_intelligence": {},
        }
        resolution = ResolutionResult(
            packages=["fastapi"],
            install_target="fastapi==0.1.0",
            resolved_versions={"fastapi": "0.1.0"},
        )

        provenance_result, scan_result = _run_fast_checks(resolution)

        self.assertTrue(provenance_result["block"])
        self.assertIn("provenance check failed unexpectedly", provenance_result["reason"])
        self.assertFalse(scan_result["block"])

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    def test_cli_install_blocks_on_resolution_failure(
        self,
        mock_resolve,
        mock_fast_checks,
    ):
        mock_resolve.return_value = ResolutionResult(
            packages=[],
            install_target="fastape",
            resolved_versions={},
            install_args=["fastape"],
            requested_targets=["fastape"],
            resolution_succeeded=False,
            resolution_error="No matching distribution found for fastape",
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["install", "fastape", "--fast", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_BLOCKED)
        self.assertIn("Resolution failed: No matching distribution found for fastape", result.output)
        self.assertIn("Host install: blocked (resolution)", result.output)
        self.assertNotIn("Provenance verdict:", result.output)
        self.assertNotIn("Scan verdict:", result.output)
        mock_fast_checks.assert_not_called()

    @patch("depshieldx.cli.prerequisites._runtime_environment_report")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    def test_cli_install_blocks_when_runtime_prerequisites_are_not_met(
        self,
        mock_resolve,
        mock_environment,
    ):
        mock_environment.return_value = {
            "block": True,
            "reason": "requires pip>=25.3 because depshieldx shells out to the local pip (running 25.2)",
            "python": {"version": "3.11.4", "required": "Python>=3.11.4", "ok": True},
            "pip": {"version": "25.2", "required": "pip>=25.3", "ok": False, "error": None},
        }

        runner = CliRunner()
        result = runner.invoke(cli, ["install", "flask", "--fast", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_BLOCKED)
        self.assertIn("Runtime prerequisite failed", result.output)
        self.assertIn("Runtime prerequisites: blocked", result.output)
        self.assertIn("Host install: blocked (environment)", result.output)
        mock_resolve.assert_not_called()

    @patch("depshieldx.cli.commands.ui.serve_ui")
    def test_cli_ui_command_passes_port_and_open_preferences(self, mock_serve_ui):
        runner = CliRunner()

        result = runner.invoke(cli, ["ui", "--port", "8123", "--no-open"])

        self.assertEqual(result.exit_code, EXIT_OK)
        mock_serve_ui.assert_called_once_with(port=8123, open_browser=False, echo=ANY)

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.host_install_command")
    @patch("depshieldx.cli.engine._run_cli_command")
    def test_cli_install_groups_warning_and_info_output(
        self,
        _mock_run_cli,
        mock_host_install_command,
        mock_resolve,
        mock_fast_checks,
    ):
        mock_host_install_command.return_value = nullcontext(["pip", "install", "--no-deps", "/tmp/Flask.whl"])
        mock_resolve.return_value = ResolutionResult(
            packages=["flask"],
            install_target="Flask==3.1.3",
            resolved_versions={"Flask": "3.1.3"},
        )
        mock_fast_checks.return_value = (
            {
                "block": False,
                "warnings": [],
                "infos": ["Flask==3.1.3: resolved release is source-only"],
                "details": [],
            },
            {
                "block": False,
                "warnings": ["deps.dev lookup unavailable: flask==3.1.3: timed out"],
                "infos": [],
            },
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["install", "flask", "--fast", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("Provenance Info:", result.output)
        self.assertIn("  - Flask==3.1.3: resolved release is source-only", result.output)
        self.assertIn("Scan Warnings:", result.output)
        self.assertIn("  - deps.dev lookup unavailable: flask==3.1.3: timed out", result.output)
        self.assertNotIn("Scan Info:", result.output)
        self.assertNotIn("Policy Info:", result.output)

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    def test_cli_scan_supports_requirements_file(
        self,
        mock_resolve_install_inputs,
        mock_fast_checks,
    ):
        mock_resolve_install_inputs.return_value = ResolutionResult(
            packages=["Flask", "Werkzeug"],
            install_target="requirements.txt",
            resolved_versions={"Flask": "3.1.3", "Werkzeug": "3.1.7"},
            install_args=["Flask==3.1.3", "Werkzeug==3.1.7"],
            requested_targets=["flask==3.1.3", "werkzeug==3.1.7"],
            source_type="requirements",
        )
        mock_fast_checks.return_value = (
            {"block": False, "warnings": [], "infos": [], "details": []},
            {"block": False, "warnings": [], "infos": []},
        )

        runner = CliRunner()
        with runner.isolated_filesystem():
            path = "requirements.txt"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("flask==3.1.3\nwerkzeug==3.1.7\n")
            result = runner.invoke(cli, ["scan", "-r", path, "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("Package: requirements.txt", result.output)
        self.assertIn("Mode: fast", result.output)
        self.assertIn("Host install: skipped (scan_only)", result.output)
        mock_fast_checks.assert_called_once()

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.cli.engine.run_sandbox")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    def test_cli_scan_deep_supports_pyproject_file(
        self,
        mock_resolve_install_inputs,
        mock_run_sandbox,
        mock_fast_checks,
    ):
        mock_resolve_install_inputs.return_value = ResolutionResult(
            packages=["Flask", "requests"],
            install_target="pyproject.toml",
            resolved_versions={"Flask": "3.1.3", "requests": "2.33.1"},
            install_args=["Flask==3.1.3", "requests==2.33.1"],
            requested_targets=["flask==3.1.3", "requests==2.33.1"],
            source_type="pyproject",
        )
        mock_fast_checks.return_value = (
            {"block": False, "warnings": [], "infos": [], "details": []},
            {"block": False, "warnings": [], "infos": []},
        )
        mock_run_sandbox.return_value = SandboxResult(
            success=True,
            downloaded_files=["Flask-3.1.3.whl", "requests-2.33.1.whl"],
            error=None,
            error_type=None,
            isolation={"backend": "docker"},
            evidence=None,
            static_analysis=None,
            bundle=None,
            cache={"hit": False, "fingerprint": "abc123"},
            trivy_results={"should_block": False, "vulnerabilities": [], "warnings": [], "scanned": True},
        )

        runner = CliRunner()
        with runner.isolated_filesystem():
            path = "pyproject.toml"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('[project]\ndependencies = ["flask==3.1.3", "requests==2.33.1"]\n')
            result = runner.invoke(cli, ["scan", "--pyproject", path, "--deep", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("Package: pyproject.toml", result.output)
        self.assertIn("Mode: deep", result.output)
        self.assertIn("Trivy verdict: passed (0 finding(s))", result.output)
        self.assertIn("Host install: skipped (scan_only)", result.output)

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    def test_cli_install_full_report_includes_json_block(
        self,
        mock_resolve,
        mock_fast_checks,
    ):
        mock_resolve.return_value = ResolutionResult(
            packages=["flask"],
            install_target="Flask==3.1.3",
            resolved_versions={"Flask": "3.1.3"},
        )
        mock_fast_checks.return_value = (
            {"block": False, "warnings": [], "infos": [], "details": []},
            {"block": True, "reason": "bad package", "warnings": [], "infos": []},
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["install", "flask", "--fast", "--full-report"])

        self.assertEqual(result.exit_code, EXIT_BLOCKED)
        self.assertIn("Summary", result.output)
        self.assertIn("Report\n{", result.output)

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.cli.engine.requests.get")
    @patch("depshieldx.cli.engine._run_cli_command")
    @patch("depshieldx.cli.engine.run_sandbox")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    def test_cli_deep_install_uses_host_pip_after_trivy_passes(
        self,
        mock_resolve,
        mock_run_sandbox,
        mock_run_cli,
        mock_requests_get,
        mock_fast_checks,
    ):
        mock_resolve.return_value = ResolutionResult(
            packages=["Flask", "Werkzeug"],
            install_target="Flask==3.1.3",
            resolved_versions={"Flask": "3.1.3", "Werkzeug": "3.1.7"},
            install_args=["Flask==3.1.3", "Werkzeug==3.1.7"],
            requested_targets=["flask"],
            selected_artifacts={
                "Flask": [
                    {
                        "filename": "Flask-3.1.3-py3-none-any.whl",
                        "url": "https://example.test/Flask-3.1.3-py3-none-any.whl",
                        "digests": {"sha256": "sha-flask"},
                    }
                ],
                "Werkzeug": [
                    {
                        "filename": "Werkzeug-3.1.7-py3-none-any.whl",
                        "url": "https://example.test/Werkzeug-3.1.7-py3-none-any.whl",
                        "digests": {"sha256": "sha-werkzeug"},
                    }
                ],
            },
        )
        mock_fast_checks.return_value = (
            {"block": False, "warnings": [], "infos": [], "details": []},
            {"block": False, "warnings": [], "infos": []},
        )
        mock_run_sandbox.return_value = SandboxResult(
            success=True,
            downloaded_files=["Flask-3.1.3.whl", "Werkzeug-3.1.7.whl"],
            error=None,
            error_type=None,
            isolation={"backend": "docker"},
            evidence=None,
            static_analysis=None,
            bundle=None,
            cache={"hit": False, "fingerprint": "abc123"},
            trivy_results={
                "should_block": False,
                "vulnerabilities": [],
                "warnings": [],
                "scanned": True,
            },
        )
        flask_resp = Mock()
        flask_resp.content = b"flask-bytes"
        flask_resp.raise_for_status.return_value = None
        werkzeug_resp = Mock()
        werkzeug_resp.content = b"werkzeug-bytes"
        werkzeug_resp.raise_for_status.return_value = None
        mock_requests_get.side_effect = [flask_resp, werkzeug_resp]

        runner = CliRunner()
        with patch("depshieldx.ecosystems.pypi.hashlib.sha256") as mock_sha256:
            mock_sha256.side_effect = [
                Mock(hexdigest=Mock(return_value="sha-flask")),
                Mock(hexdigest=Mock(return_value="sha-werkzeug")),
            ]
            result = runner.invoke(cli, ["install", "flask", "--deep", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("Trivy verdict: passed (0 finding(s))", result.output)
        install_command = mock_run_cli.call_args.args[0]
        self.assertEqual(install_command[:5], [sys.executable, "-m", "pip", "install", "--no-deps"])
        self.assertEqual(
            [Path(value).name for value in install_command[5:]],
            ["Flask-3.1.3-py3-none-any.whl", "Werkzeug-3.1.7-py3-none-any.whl"],
        )
        self.assertEqual(mock_run_cli.call_args.kwargs, {"verbose": False})

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.cli.engine._run_cli_command")
    @patch("depshieldx.cli.engine.run_sandbox")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    def test_cli_deep_install_blocks_on_trivy(
        self,
        mock_resolve,
        mock_run_sandbox,
        mock_run_cli,
        mock_fast_checks,
    ):
        mock_resolve.return_value = ResolutionResult(
            packages=["Flask"],
            install_target="Flask==3.1.3",
            resolved_versions={"Flask": "3.1.3"},
            install_args=["Flask==3.1.3"],
            requested_targets=["flask"],
        )
        mock_fast_checks.return_value = (
            {"block": False, "warnings": [], "infos": [], "details": []},
            {"block": False, "warnings": [], "infos": []},
        )
        mock_run_sandbox.return_value = SandboxResult(
            success=False,
            downloaded_files=["Flask-3.1.3.whl"],
            error="Trivy found HIGH/CRITICAL vulnerabilities or secrets in the sandboxed installation.",
            error_type="trivy",
            isolation={"backend": "docker"},
            evidence=None,
            static_analysis=None,
            bundle=None,
            cache={"hit": False, "fingerprint": "abc123"},
            trivy_results={
                "should_block": True,
                "vulnerabilities": [{"id": "CVE-2026-1234", "severity": "HIGH"}],
                "warnings": [],
                "scanned": True,
            },
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["install", "flask", "--deep", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_BLOCKED)
        self.assertIn("Installation blocked by Trivy", result.output)
        self.assertIn("Trivy verdict: blocked (1 finding(s))", result.output)
        self.assertIn("First Trivy finding: HIGH CVE-2026-1234", result.output)
        mock_run_cli.assert_not_called()

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.cli.engine.run_sandbox")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    def test_cli_deep_install_blocks_on_preinstall_vulnerability(
        self,
        mock_resolve,
        mock_run_sandbox,
        mock_fast_checks,
    ):
        mock_resolve.return_value = ResolutionResult(
            packages=["Flask", "Werkzeug"],
            install_target="Flask==3.1.3",
            resolved_versions={"Flask": "3.1.3", "Werkzeug": "3.1.7"},
            install_args=["Flask==3.1.3", "Werkzeug==3.1.7"],
            requested_targets=["flask"],
        )
        mock_fast_checks.return_value = (
            {"block": False, "warnings": [], "infos": [], "details": []},
            {"block": True, "reason": "Werkzeug==3.1.7 has reported vulnerabilities: CVE-2026-1234", "warnings": [], "infos": []},
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["install", "flask", "--deep", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_BLOCKED)
        self.assertIn("BLOCKED: Werkzeug==3.1.7 has reported vulnerabilities: CVE-2026-1234", result.output)
        self.assertIn("Host install: blocked (scan)", result.output)
        mock_run_sandbox.assert_not_called()

    @patch("depshieldx.cli.engine.subprocess_env", return_value={"FAKE_ENV": "1"})
    @patch("depshieldx.cli.engine.subprocess.run")
    def test_run_cli_command_is_quiet_by_default(self, mock_run, _mock_subprocess_env):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["pip", "install", "flask"],
            returncode=0,
            stdout="installed\n",
            stderr="",
        )

        result = _run_cli_command(["pip", "install", "flask"])

        self.assertEqual(result.stdout, "installed\n")
        mock_run.assert_called_once_with(
            ["pip", "install", "flask"],
            check=True,
            capture_output=True,
            text=True,
            env={"FAKE_ENV": "1"},
        )

    @patch("depshieldx.cli.engine.subprocess_env", return_value={"FAKE_ENV": "1"})
    @patch("depshieldx.cli.engine.subprocess.run")
    def test_run_cli_command_streams_when_verbose(self, mock_run, _mock_subprocess_env):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["pip", "install", "flask"],
            returncode=0,
            stdout=None,
            stderr=None,
        )

        _run_cli_command(["pip", "install", "flask"], verbose=True)

        mock_run.assert_called_once_with(
            ["pip", "install", "flask"],
            check=True,
            capture_output=False,
            text=False,
            env={"FAKE_ENV": "1"},
        )

    def test_determine_exit_code_for_success_report(self):
        report = {"install": {"success": True}}

        exit_code = _determine_exit_code(report)

        self.assertEqual(exit_code, EXIT_OK)

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.host_install_command")
    @patch("depshieldx.cli.engine._run_cli_command")
    @patch("depshieldx.cli.engine.enable_routing_shim")
    def test_cli_install_enable_routing_flag_enables_shim(
        self,
        mock_enable_routing,
        _mock_run_cli,
        mock_host_install_command,
        mock_resolve,
        mock_fast_checks,
    ):
        mock_host_install_command.return_value = nullcontext(["pip", "install", "--no-deps", "/tmp/Flask.whl"])
        mock_resolve.return_value = ResolutionResult(
            packages=["flask"],
            install_target="Flask==3.1.3",
            resolved_versions={"Flask": "3.1.3"},
        )
        mock_fast_checks.return_value = (
            {"block": False, "warnings": [], "infos": [], "details": []},
            {"block": False, "warnings": [], "infos": []},
        )
        mock_enable_routing.return_value = {
            "enabled": True,
            "activation_hint": 'export PATH="/tmp/shims:$PATH"',
        }

        runner = CliRunner()
        result = runner.invoke(cli, ["install", "flask", "--fast", "--enable-routing", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_OK)
        mock_enable_routing.assert_called_once()
        self.assertIn("pip routing enabled", result.output)

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.host_install_command")
    @patch("depshieldx.cli.engine._run_cli_command")
    @patch("depshieldx.cli.engine.disable_routing_shim")
    def test_cli_install_disable_routing_flag_disables_shim(
        self,
        mock_disable_routing,
        _mock_run_cli,
        mock_host_install_command,
        mock_resolve,
        mock_fast_checks,
    ):
        mock_host_install_command.return_value = nullcontext(["pip", "install", "--no-deps", "/tmp/Flask.whl"])
        mock_resolve.return_value = ResolutionResult(
            packages=["flask"],
            install_target="Flask==3.1.3",
            resolved_versions={"Flask": "3.1.3"},
        )
        mock_fast_checks.return_value = (
            {"block": False, "warnings": [], "infos": [], "details": []},
            {"block": False, "warnings": [], "infos": []},
        )
        mock_disable_routing.return_value = {"enabled": False}

        runner = CliRunner()
        result = runner.invoke(cli, ["install", "flask", "--fast", "--disable-routing", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_OK)
        mock_disable_routing.assert_called_once()
        self.assertIn("pip routing disabled", result.output)

    @patch("depshieldx.cli.engine.enable_routing_shim")
    @patch("depshieldx.cli.engine.should_prompt_for_routing", return_value=True)
    @patch("depshieldx.cli.engine.click.confirm", return_value=True)
    @patch("depshieldx.cli.engine.sys.stdout.isatty", return_value=True)
    @patch("depshieldx.cli.engine.sys.stdin.isatty", return_value=True)
    def test_handle_routing_choice_prompts_and_accepts_yes(
        self,
        _mock_stdin_tty,
        _mock_stdout_tty,
        mock_confirm,
        _mock_should_prompt,
        mock_enable_routing,
    ):
        mock_enable_routing.return_value = {
            "enabled": True,
            "activation_hint": 'export PATH="/tmp/shims:$PATH"',
        }

        _handle_routing_choice()

        mock_confirm.assert_called_once()
        mock_enable_routing.assert_called_once()

    @patch("depshieldx.cli.engine.dismiss_routing_prompt")
    @patch("depshieldx.cli.engine.enable_routing_shim")
    @patch("depshieldx.cli.engine.should_prompt_for_routing", return_value=True)
    @patch("depshieldx.cli.engine.click.confirm", return_value=False)
    @patch("depshieldx.cli.engine.sys.stdout.isatty", return_value=True)
    @patch("depshieldx.cli.engine.sys.stdin.isatty", return_value=True)
    def test_handle_routing_choice_dismisses_prompt_on_no(
        self,
        _mock_stdin_tty,
        _mock_stdout_tty,
        mock_confirm,
        _mock_should_prompt,
        mock_enable_routing,
        mock_dismiss,
    ):
        mock_dismiss.return_value = {
            "enabled": False,
            "prompt_dismissed": True,
            "activation_hint": 'export PATH="/tmp/shims:$PATH"',
        }

        _handle_routing_choice()

        mock_confirm.assert_called_once()
        mock_enable_routing.assert_not_called()
        mock_dismiss.assert_called_once()

    @patch("depshieldx.cli.engine.enable_routing_shim")
    @patch("depshieldx.cli.engine.should_prompt_for_routing", return_value=True)
    @patch("depshieldx.cli.engine.click.confirm", return_value=True)
    @patch("depshieldx.cli.engine.click.echo")
    @patch("depshieldx.cli.engine.sys.stdout.isatty", return_value=True)
    @patch("depshieldx.cli.engine.sys.stdin.isatty", return_value=True)
    def test_handle_routing_choice_prompts_with_onboarding_for_depshieldx_install(
        self,
        _mock_stdin_tty,
        _mock_stdout_tty,
        mock_echo,
        mock_confirm,
        _mock_should_prompt,
        mock_enable_routing,
    ):
        mock_enable_routing.return_value = {
            "enabled": True,
            "activation_hint": 'export PATH="/tmp/shims:$PATH"',
        }

        _handle_routing_choice(package_name="depshieldx")

        mock_confirm.assert_called_once_with("Enable optional pip routing now?", default=False)
        mock_enable_routing.assert_called_once()
        echoed_lines = [call.args[0] for call in mock_echo.call_args_list if call.args]
        self.assertIn(
            "Optional pip routing can send simple 'pip install <package>' commands through depshieldx.",
            echoed_lines,
        )
        self.assertIn("Enable later with: depshieldx routing enable", echoed_lines)
        self.assertIn("Disable later with: depshieldx routing disable", echoed_lines)

    def test_should_prompt_for_routing_is_false_when_prompt_is_dismissed(self):
        with patch("depshieldx.routing.get_routing_status", return_value={"enabled": False, "prompt_dismissed": True}):
            self.assertFalse(should_prompt_for_routing())

    @patch("depshieldx.cli.engine.click.echo")
    def test_finalize_routing_after_install_shows_status_for_depshieldx(self, mock_echo):
        _finalize_routing_after_install(
            "depshieldx",
            routing_status={
                "enabled": True,
                "activation_hint": 'export PATH="/tmp/shims:$PATH"',
            },
        )

        echoed_lines = [call.args[0] for call in mock_echo.call_args_list if call.args]
        self.assertIn("Routing status: enabled", echoed_lines)
        self.assertIn("Manage later with: depshieldx routing enable | depshieldx routing disable", echoed_lines)
        self.assertIn('Activation: export PATH="/tmp/shims:$PATH"', echoed_lines)

    @patch("depshieldx.cli.engine._run_fast_checks")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.resolve")
    @patch("depshieldx.ecosystems.PYPI_ECOSYSTEM.host_install_command")
    @patch("depshieldx.cli.engine._run_cli_command")
    @patch("depshieldx.cli.engine._finalize_routing_after_install")
    @patch("depshieldx.cli.engine._prepare_routing_for_install")
    def test_cli_install_depshieldx_prepares_routing_before_install(
        self,
        mock_prepare_routing,
        mock_finalize_routing,
        mock_run_cli,
        mock_host_install_command,
        mock_resolve,
        mock_fast_checks,
    ):
        call_order = []
        mock_host_install_command.return_value = nullcontext(["pip", "install", "--no-deps", "/tmp/depshieldx.whl"])
        mock_resolve.return_value = ResolutionResult(
            packages=["depshieldx"],
            install_target="depshieldx==0.1.0",
            resolved_versions={"depshieldx": "0.1.0"},
        )
        mock_fast_checks.return_value = (
            {"block": False, "warnings": [], "infos": [], "details": []},
            {"block": False, "warnings": [], "infos": []},
        )
        mock_prepare_routing.side_effect = lambda *args, **kwargs: call_order.append("prepare") or {"enabled": False}
        mock_run_cli.side_effect = lambda *args, **kwargs: call_order.append("install") or subprocess.CompletedProcess(args=[], returncode=0)
        mock_finalize_routing.side_effect = lambda *args, **kwargs: call_order.append("finalize") or {"enabled": False}

        runner = CliRunner()
        result = runner.invoke(cli, ["install", "depshieldx", "--fast", "--output", "summary"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertEqual(call_order, ["prepare", "install", "finalize"])

    @patch("depshieldx.cli.commands.routing.get_routing_status")
    def test_routing_status_command_prints_state(self, mock_status):
        mock_status.return_value = {
            "enabled": True,
            "shim_path": "/tmp/shims/pip",
            "activation_hint": 'export PATH="/tmp/shims:$PATH"',
        }

        runner = CliRunner()
        result = runner.invoke(cli, ["routing", "status"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("Routing: enabled", result.output)
        self.assertIn("/tmp/shims/pip", result.output)

    @patch("depshieldx.cli.commands.routing.subprocess_env", return_value={"FAKE_ENV": "1"})
    @patch("depshieldx.cli.commands.routing.subprocess.run")
    def test_route_pip_routes_simple_install_to_depshieldx(self, mock_run, _mock_subprocess_env):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        runner = CliRunner()
        result = runner.invoke(cli, ["route-pip", "install", "flask"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(
            [sys.executable, "-m", "depshieldx.cli", "install", "flask"],
            check=False,
            env={"FAKE_ENV": "1"},
        )
        self.assertIn("Routing pip install through depshieldx", result.output)

    @patch("depshieldx.cli.commands.receipts.list_receipts")
    def test_receipts_list_command_prints_receipts(self, mock_list_receipts):
        mock_list_receipts.return_value = [
            {
                "created_at": "2026-03-26T12:00:00+00:00",
                "decision": "allowed",
                "package": "flask",
                "receipt_id": "abc123",
                "path": "/tmp/receipt.json",
            }
        ]

        runner = CliRunner()
        result = runner.invoke(cli, ["receipts", "list", "--limit", "5"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("2026-03-26T12:00:00+00:00  allowed  flask  abc123", result.output)
        self.assertIn("/tmp/receipt.json", result.output)

    @patch("depshieldx.cli.commands.receipts.verify_receipt", return_value={"valid": True, "path": "/tmp/receipt.json"})
    def test_receipts_verify_command_returns_success(self, mock_verify_receipt):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("receipt.json", "w", encoding="utf-8") as fh:
                fh.write("{}")
            result = runner.invoke(cli, ["receipts", "verify", "receipt.json"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("Receipt valid: /tmp/receipt.json", result.output)
        mock_verify_receipt.assert_called_once()

    @patch("depshieldx.cli.commands.receipts.verify_receipt", return_value={"valid": False, "path": "/tmp/receipt.json"})
    def test_receipts_verify_command_returns_blocked_for_invalid_receipt(self, mock_verify_receipt):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("receipt.json", "w", encoding="utf-8") as fh:
                fh.write("{}")
            result = runner.invoke(cli, ["receipts", "verify", "receipt.json"])

        self.assertEqual(result.exit_code, EXIT_BLOCKED)
        self.assertIn("Receipt invalid: /tmp/receipt.json", result.output)
        mock_verify_receipt.assert_called_once()

    @patch("depshieldx.cli.commands.receipts.delete_receipts", return_value=4)
    def test_receipts_delete_command_reports_deleted_count(self, mock_delete_receipts):
        runner = CliRunner()
        result = runner.invoke(cli, ["receipts", "delete"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("Deleted 4 receipt(s).", result.output)
        mock_delete_receipts.assert_called_once()

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    @patch("depshieldx.cli.engine.load_input_source")
    def test_uninstall_uses_package_names_from_targets(self, mock_load_input_source, mock_run_cli):
        from depshieldx.input_sources import InputSource

        mock_load_input_source.return_value = InputSource(
            source_type="packages",
            label="langchain, requests",
            requested_targets=["langchain==1.2.13", "requests>=2.0"],
            pip_args=["langchain==1.2.13", "requests>=2.0"],
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["uninstall", "langchain", "requests"])

        self.assertEqual(result.exit_code, EXIT_OK)
        mock_run_cli.assert_called_once_with(
            [sys.executable, "-m", "pip", "uninstall", "-y", "langchain", "requests"], verbose=False
        )
        self.assertIn("Uninstall completed.", result.output)

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    @patch("depshieldx.cli.engine.load_input_source")
    def test_uninstall_supports_requirements_file(self, mock_load_input_source, mock_run_cli):
        from depshieldx.input_sources import InputSource

        mock_load_input_source.return_value = InputSource(
            source_type="requirements",
            label="requirements.txt",
            requested_targets=["flask==3.1.3", "requests==2.33.1"],
            pip_args=["-r", "requirements.txt"],
        )

        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("requirements.txt", "w", encoding="utf-8") as fh:
                fh.write("flask==3.1.3\nrequests==2.33.1\n")
            result = runner.invoke(cli, ["uninstall", "-r", "requirements.txt"])

        self.assertEqual(result.exit_code, EXIT_OK)
        mock_run_cli.assert_called_once_with(
            [sys.executable, "-m", "pip", "uninstall", "-y", "-r", "requirements.txt"], verbose=False
        )
        self.assertIn("Removed packages listed in requirements.txt.", result.output)
