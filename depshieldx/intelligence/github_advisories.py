"""GitHub Security Advisories source client."""

import asyncio
from typing import Dict, List, Optional, Tuple

import requests
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .common import _normalize_name

GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"

# depshieldx's internal ecosystem key -> GitHub's own naming convention.
# GHSA uses "pip", deps.dev uses "pypi", OSV uses "PyPI" -- see osv.OSV_ECOSYSTEM_NAMES
# -- so each source needs its own lookup.
GITHUB_ADVISORY_ECOSYSTEM_NAMES = {
    "pypi": "pip",
    "npm": "npm",
}


def _is_version_affected(version: str | None, vulnerable_range: str | None) -> bool:
    if not vulnerable_range:
        return True
    if not version:
        return True

    normalized_range = ",".join(
        part.strip().replace("=", "==", 1) if part.strip().startswith("=") and not part.strip().startswith("==") else part.strip()
        for part in vulnerable_range.split(",")
        if part.strip()
    )
    try:
        specifiers = SpecifierSet(normalized_range)
        candidate = Version(version)
    except (InvalidSpecifier, InvalidVersion):
        return True
    return candidate in specifiers


def fetch_github_advisories(
    packages: list[str], resolved_versions: dict[str, str] | None = None, ecosystem: str = "pypi"
) -> dict:
    normalized_packages = sorted({_normalize_name(package, ecosystem) for package in packages if package})
    resolved_versions = {
        _normalize_name(name, ecosystem): version
        for name, version in (resolved_versions or {}).items()
        if version
    }
    if not normalized_packages:
        return {"hits": [], "warnings": [], "source": "github_advisories"}

    try:
        response = requests.get(
            GITHUB_ADVISORIES_URL,
            params={
                "ecosystem": GITHUB_ADVISORY_ECOSYSTEM_NAMES.get(ecosystem, "pip"),
                "affects": ",".join(normalized_packages),
                "per_page": 100,
            },
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=4,
        )
        response.raise_for_status()
        advisories = response.json()
    except Exception as exc:
        return {
            "hits": [],
            "warnings": [f"github advisory lookup unavailable: {exc}"],
            "source": "github_advisories",
        }

    hits = []
    seen = set()
    for advisory in advisories:
        for vulnerability in advisory.get("vulnerabilities", []):
            package = _normalize_name(vulnerability.get("package", {}).get("name", ""), ecosystem)
            if package not in normalized_packages:
                continue
            resolved_version = resolved_versions.get(package)
            vulnerable_range = vulnerability.get("vulnerable_version_range")
            if not _is_version_affected(resolved_version, vulnerable_range):
                continue
            hit = {
                "package": package,
                "package_version": resolved_version,
                "ghsa_id": advisory.get("ghsa_id"),
                "cve_id": advisory.get("cve_id"),
                "severity": (advisory.get("severity") or "unknown").upper(),
                "summary": advisory.get("summary"),
                "vulnerable_version_range": vulnerable_range,
                "first_patched_version": vulnerability.get("first_patched_version"),
                "epss": advisory.get("epss") or [],
                "source": "github_advisories",
            }
            dedupe_key = (hit["package"], hit["ghsa_id"], hit["cve_id"])
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            hits.append(hit)

    return {"hits": hits, "warnings": [], "source": "github_advisories"}


async def _async_fetch_github_advisories(
    packages: List[str], resolved_versions: Optional[Dict[str, str]] = None, ecosystem: str = "pypi"
) -> Tuple[str, Dict]:
    """Async wrapper: Fetch GitHub Security Advisories with timeout protection."""
    try:
        loop = asyncio.get_event_loop()
        # Use lambda to properly pass keyword arguments through executor
        result = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: fetch_github_advisories(packages, resolved_versions=resolved_versions, ecosystem=ecosystem)
            ),
            timeout=15.0  # 15 second timeout
        )
        return "github-advisories", result
    except asyncio.TimeoutError:
        return "github-advisories", {"hits": [], "warnings": ["GitHub advisory lookup unavailable: timeout"]}
    except Exception:
        return "github-advisories", {"hits": [], "warnings": ["GitHub advisory lookup unavailable"]}
