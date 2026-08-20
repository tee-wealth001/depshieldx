"""deps.dev (https://deps.dev) source client."""

import asyncio
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

from .common import _normalize_name

DEPS_DEV_VERSION_URL_TEMPLATES = (
    "https://api.deps.dev/v3/systems/{system}/packages/{package}/versions/{version}",
    "https://api.deps.dev/v3alpha/systems/{system}/packages/{package}/versions/{version}",
)

# depshieldx's internal ecosystem key -> deps.dev's own naming convention.
DEPS_DEV_SYSTEM_NAMES = {
    "pypi": "pypi",
    "npm": "npm",
    "cargo": "cargo",
    "go": "go",
    "maven": "maven",
    "nuget": "nuget",
}


def _deps_dev_version_payload(package: str, version: str, ecosystem: str = "pypi") -> tuple[dict | None, str | None]:
    encoded_package = quote(package, safe="")
    encoded_version = quote(version, safe="")
    system = DEPS_DEV_SYSTEM_NAMES.get(ecosystem, "pypi")
    last_error = None
    for template in DEPS_DEV_VERSION_URL_TEMPLATES:
        try:
            response = requests.get(
                template.format(system=system, package=encoded_package, version=encoded_version),
                timeout=5,  # Increased from 4
            )
            response.raise_for_status()
            return response.json(), None
        except Exception as exc:
            last_error = exc
    return None, str(last_error) if last_error else "unknown deps.dev error"


def _extract_deps_dev_advisories(payload: dict) -> list[dict]:
    advisories = payload.get("advisories") or (payload.get("version") or {}).get("advisories") or []
    hits = []
    for advisory in advisories:
        advisory = advisory or {}
        advisory_id = (
            advisory.get("id")
            or advisory.get("sourceID")
            or advisory.get("advisoryId")
            or advisory.get("ghsaId")
            or advisory.get("cve")
        )
        hits.append(
            {
                "id": advisory_id,
                "title": advisory.get("title") or advisory.get("summary"),
            }
        )
    return hits


def _extract_deps_dev_dependency_count(payload: dict) -> int:
    dependencies = payload.get("dependencies")
    if isinstance(dependencies, list):
        return len(dependencies)

    version = payload.get("version") or {}
    version_dependencies = version.get("dependencies")
    if isinstance(version_dependencies, list):
        return len(version_dependencies)
    return 0


def fetch_deps_dev_insights(
    packages: list[str], resolved_versions: dict[str, str] | None = None, ecosystem: str = "pypi"
) -> dict:
    if ecosystem not in DEPS_DEV_SYSTEM_NAMES:
        # deps.dev has no Pub system at all (confirmed directly against
        # docs.deps.dev/api/v3's supported systems list: GO, RUBYGEMS,
        # NPM, CARGO, MAVEN, PYPI, NUGET -- no Pub). The DEPS_DEV_SYSTEM_
        # NAMES.get(ecosystem, "pypi") pattern below would otherwise
        # silently query deps.dev's *PyPI* system using a Pub package's
        # name, which isn't "no results" so much as "meaningless
        # results" -- skip explicitly instead of risking that.
        return {"hits": [], "warnings": [], "source": "deps_dev"}

    normalized_versions = {
        _normalize_name(name, ecosystem): version
        for name, version in (resolved_versions or {}).items()
        if version
    }
    hits = []
    warnings = []

    for package in packages:
        normalized_name = _normalize_name(package, ecosystem)
        version = normalized_versions.get(normalized_name)
        if not version:
            continue

        payload, error = _deps_dev_version_payload(normalized_name, version, ecosystem)
        if error or not payload:
            warnings.append(f"deps.dev lookup unavailable: {package}=={version}: {error}")
            continue

        advisories = _extract_deps_dev_advisories(payload)
        hits.append(
            {
                "package": normalized_name,
                "package_version": version,
                "dependency_count": _extract_deps_dev_dependency_count(payload),
                "advisory_count": len(advisories),
                "advisories": advisories,
                "source": "deps_dev",
            }
        )

    return {"hits": hits, "warnings": warnings, "source": "deps_dev"}


async def _async_fetch_deps_dev_cves(
    packages: List[str], resolved_versions: Optional[Dict[str, str]] = None, ecosystem: str = "pypi"
) -> Tuple[str, Dict]:
    """Async wrapper: Fetch insights from deps.dev with timeout protection."""
    try:
        loop = asyncio.get_event_loop()
        # Use lambda to properly pass keyword arguments through executor
        result = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: fetch_deps_dev_insights(packages, resolved_versions=resolved_versions, ecosystem=ecosystem)
            ),
            timeout=15.0  # 15 second timeout
        )
        return "deps-dev", result
    except asyncio.TimeoutError:
        return "deps-dev", {"hits": [], "warnings": ["deps.dev lookup unavailable: timeout"]}
    except Exception:
        return "deps-dev", {"hits": [], "warnings": ["deps.dev lookup unavailable"]}
