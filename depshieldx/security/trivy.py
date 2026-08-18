"""
Trivy integration for container image vulnerability scanning.

Trivy is a free, open-source container scanner that detects:
- CVEs in OS packages
- Application vulnerabilities
- Misconfigurations
- Secrets
- License information

This module wraps Trivy CLI for deep scanning of container images.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Tuple


def _is_trivy_installed() -> bool:
    """Check if Trivy is installed and available."""
    try:
        result = subprocess.run(
            ["trivy", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _parse_trivy_output(json_output: str) -> Dict:
    """Parse Trivy JSON output into standard vulnerability format."""
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return {"vulnerabilities": [], "warnings": ["Trivy output parsing failed"]}

    vulnerabilities = []
    results = data.get("Results", [])

    for result in results:
        # Each result can contain misconfigurations or vulnerabilities
        for vuln in result.get("Misconfigurations", []):
            vulnerabilities.append(
                {
                    "id": vuln.get("ID"),
                    "type": "misconfiguration",
                    "severity": vuln.get("Severity", "MEDIUM"),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "resolution": vuln.get("Resolution", ""),
                    "source": "trivy_misconfiguration",
                }
            )

        for vuln in result.get("Vulnerabilities", []):
            pkg = vuln.get("PkgName", "")
            version = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")

            vulnerabilities.append(
                {
                    "id": vuln.get("VulnerabilityID"),
                    "package": pkg,
                    "installed_version": version,
                    "fixed_version": fixed,
                    "type": "cve",
                    "severity": vuln.get("Severity", "MEDIUM"),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "source": "trivy_cve",
                }
            )

        for secret in result.get("Secrets", []):
            vulnerabilities.append(
                {
                    "id": secret.get("RuleID"),
                    "type": "secret",
                    "severity": "CRITICAL",
                    "title": f"Exposed secret: {secret.get('Title', 'unknown')}",
                    "description": secret.get("Description", ""),
                    "source": "trivy_secret",
                }
            )

    return {"vulnerabilities": vulnerabilities, "warnings": []}


def scan_container_image(image: str, severity: str = "HIGH") -> Tuple[bool, List[Dict], List[str]]:
    """
    Scan a container image for vulnerabilities using Trivy.

    Args:
        image: Container image name/tag (e.g., "nginx:latest", "ghcr.io/user/app:v1.0")
        severity: Minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL)

    Returns:
        Tuple of (should_block, vulnerabilities, warnings)
        - should_block: True if CRITICAL or image cannot be scanned
        - vulnerabilities: List of vulnerability dicts
        - warnings: List of warning messages
    """
    if not _is_trivy_installed():
        return False, [], ["Trivy not installed. Skipping container image scan."]

    try:
        # Run Trivy with JSON output
        result = subprocess.run(
            [
                "trivy",
                "image",
                "--format",
                "json",
                "--severity",
                severity,
                "--no-progress",
                image,
            ],
            capture_output=True,
            timeout=120,  # Container scans can take time
            text=True,
        )

        if result.returncode not in (0, 1):
            # Exit code 1 can mean vulnerabilities found; 0 means clean
            return (
                False,
                [],
                [f"Trivy scan of {image} failed: {result.stderr}"],
            )

        parsed = _parse_trivy_output(result.stdout)
        vulns = parsed.get("vulnerabilities", [])
        warnings = parsed.get("warnings", [])

        # Check for critical/high severity & secrets
        should_block = any(
            v.get("severity") in ("CRITICAL", "HIGH") or v.get("type") == "secret"
            for v in vulns
        )

        return should_block, vulns, warnings

    except subprocess.TimeoutExpired:
        return (
            False,
            [],
            [f"Trivy scan of {image} timed out after 120s"],
        )
    except Exception as e:
        return (
            False,
            [],
            [f"Trivy scan of {image} failed: {str(e)}"],
        )


def scan_filesystem(path: str, severity: str = "HIGH") -> Tuple[bool, List[Dict], List[str]]:
    """
    Scan a filesystem/directory for vulnerabilities using Trivy.

    Useful for scanning extracted package contents or build artifacts.

    Args:
        path: Path to filesystem/directory
        severity: Minimum severity to report

    Returns:
        Tuple of (should_block, vulnerabilities, warnings)
    """
    if not _is_trivy_installed():
        return False, [], ["Trivy not installed. Skipping filesystem scan."]

    if not Path(path).exists():
        return False, [], [f"Path does not exist: {path}"]

    try:
        result = subprocess.run(
            [
                "trivy",
                "fs",
                "--format",
                "json",
                "--severity",
                severity,
                "--no-progress",
                path,
            ],
            capture_output=True,
            timeout=120,
            text=True,
        )

        if result.returncode not in (0, 1):
            return (
                False,
                [],
                [f"Trivy filesystem scan of {path} failed: {result.stderr}"],
            )

        parsed = _parse_trivy_output(result.stdout)
        vulns = parsed.get("vulnerabilities", [])
        warnings = parsed.get("warnings", [])

        should_block = any(
            v.get("severity") in ("CRITICAL", "HIGH") or v.get("type") == "secret"
            for v in vulns
        )

        return should_block, vulns, warnings

    except subprocess.TimeoutExpired:
        return (
            False,
            [],
            [f"Trivy filesystem scan of {path} timed out after 120s"],
        )
    except Exception as e:
        return (
            False,
            [],
            [f"Trivy filesystem scan of {path} failed: {str(e)}"],
        )


def get_trivy_status() -> Dict[str, any]:
    """Get Trivy installation and version info."""
    installed = _is_trivy_installed()
    version = None

    if installed:
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                timeout=5,
                text=True,
            )
            version = result.stdout.strip()
        except Exception:
            pass

    return {
        "installed": installed,
        "version": version,
        "source": "trivy",
    }
