import unittest
from unittest.mock import patch, MagicMock

from depshieldx.trivy import (
    scan_container_image,
    scan_filesystem,
    get_trivy_status,
    _is_trivy_installed,
)


class TrivyTests(unittest.TestCase):
    @patch("depshieldx.trivy.subprocess.run")
    def test_is_trivy_installed_returns_true_when_trivy_available(self, mock_run):
        """Test that _is_trivy_installed returns True when trivy --version succeeds."""
        mock_run.return_value = MagicMock(returncode=0)

        result = _is_trivy_installed()

        self.assertTrue(result)
        mock_run.assert_called_once()

    @patch("depshieldx.trivy.subprocess.run")
    def test_is_trivy_installed_returns_false_when_trivy_missing(self, mock_run):
        """Test that _is_trivy_installed returns False when trivy not found."""
        mock_run.side_effect = FileNotFoundError()

        result = _is_trivy_installed()

        self.assertFalse(result)

    @patch("depshieldx.trivy._is_trivy_installed", return_value=False)
    def test_scan_container_image_returns_warning_when_trivy_missing(self, mock_installed):
        """Test that scan_container_image returns warning when Trivy is not installed."""
        should_block, vulns, warnings = scan_container_image("nginx:latest")

        self.assertFalse(should_block)
        self.assertEqual(vulns, [])
        self.assertIn("Trivy not installed", warnings[0])

    @patch("depshieldx.trivy._is_trivy_installed", return_value=True)
    @patch("depshieldx.trivy.subprocess.run")
    def test_scan_container_image_parses_vulnerabilities(self, mock_run, mock_installed):
        """Test that scan_container_image correctly parses Trivy output."""
        trivy_output = """{
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-1234",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1k",
                            "FixedVersion": "1.1.1l",
                            "Severity": "HIGH",
                            "Title": "OpenSSL vulnerability",
                            "Description": "Test vulnerability"
                        }
                    ],
                    "Misconfigurations": [],
                    "Secrets": []
                }
            ]
        }"""
        mock_run.return_value = MagicMock(returncode=0, stdout=trivy_output)

        should_block, vulns, warnings = scan_container_image("nginx:latest")

        self.assertTrue(should_block)  # HIGH severity should block
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["id"], "CVE-2021-1234")
        self.assertEqual(vulns[0]["severity"], "HIGH")
        self.assertEqual(vulns[0]["package"], "openssl")

    @patch("depshieldx.trivy._is_trivy_installed", return_value=True)
    @patch("depshieldx.trivy.subprocess.run")
    def test_scan_container_image_detects_secrets(self, mock_run, mock_installed):
        """Test that scan_container_image detects exposed secrets."""
        trivy_output = """{
            "Results": [
                {
                    "Vulnerabilities": [],
                    "Misconfigurations": [],
                    "Secrets": [
                        {
                            "RuleID": "secret-1",
                            "Title": "AWS Access Key",
                            "Description": "Exposed AWS credentials"
                        }
                    ]
                }
            ]
        }"""
        mock_run.return_value = MagicMock(returncode=0, stdout=trivy_output)

        should_block, vulns, warnings = scan_container_image("nginx:latest")

        self.assertTrue(should_block)  # Secrets should always block (CRITICAL)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["type"], "secret")
        self.assertEqual(vulns[0]["severity"], "CRITICAL")

    @patch("depshieldx.trivy._is_trivy_installed", return_value=True)
    @patch("depshieldx.trivy.subprocess.run")
    def test_scan_container_image_detects_misconfigurations(self, mock_run, mock_installed):
        """Test that scan_container_image detects security misconfigurations."""
        trivy_output = """{
            "Results": [
                {
                    "Vulnerabilities": [],
                    "Misconfigurations": [
                        {
                            "ID": "AVD-AZU-0001",
                            "Severity": "HIGH",
                            "Title": "Container running as root",
                            "Description": "Container is running with root privileges",
                            "Resolution": "Add USER directive to Dockerfile"
                        }
                    ],
                    "Secrets": []
                }
            ]
        }"""
        mock_run.return_value = MagicMock(returncode=0, stdout=trivy_output)

        should_block, vulns, warnings = scan_container_image("nginx:latest")

        self.assertTrue(should_block)  # HIGH severity should block
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["type"], "misconfiguration")
        self.assertEqual(vulns[0]["severity"], "HIGH")

    @patch("depshieldx.trivy._is_trivy_installed", return_value=True)
    @patch("depshieldx.trivy.subprocess.run")
    def test_scan_container_image_handles_timeout(self, mock_run, mock_installed):
        """Test that scan_container_image handles timeout gracefully."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("trivy", 120)

        should_block, vulns, warnings = scan_container_image("nginx:latest")

        self.assertFalse(should_block)
        self.assertEqual(vulns, [])
        self.assertIn("timed out", warnings[0])

    @patch("depshieldx.trivy._is_trivy_installed", return_value=True)
    @patch("depshieldx.trivy.subprocess.run")
    def test_get_trivy_status_returns_version(self, mock_run, mock_installed):
        """Test that get_trivy_status returns Trivy version info."""
        mock_run.return_value = MagicMock(returncode=0, stdout="Trivy version 0.50.0")

        status = get_trivy_status()

        self.assertTrue(status["installed"])
        self.assertIn("0.50.0", status["version"])
        self.assertEqual(status["source"], "trivy")

    @patch("depshieldx.trivy._is_trivy_installed", return_value=False)
    def test_get_trivy_status_returns_not_installed(self, mock_installed):
        """Test that get_trivy_status indicates when Trivy is not installed."""
        status = get_trivy_status()

        self.assertFalse(status["installed"])
        self.assertIsNone(status["version"])
        self.assertEqual(status["source"], "trivy")
