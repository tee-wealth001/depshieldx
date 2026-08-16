"""Consolidated multi-source lookup -- the one real entry point scanner.py uses."""

import asyncio
from typing import Dict, List, Optional

from .cisa_kev import _async_fetch_cisa_kev_cves
from .deps_dev import _async_fetch_deps_dev_cves
from .github_advisories import _async_fetch_github_advisories
from .osv import _async_fetch_osv_cves


async def _fetch_all_sources_for_packages_concurrent(
    packages: List[str], resolved_versions: Optional[Dict[str, str]] = None, ecosystem: str = "pypi"
) -> Dict[str, any]:
    """
    Fetch from all sources concurrently for multiple packages.
    Handles both per-package (OSV, CISA KEV) and batch-level (GitHub, deps.dev) fetches.
    """
    tasks = []

    # Per-package concurrent fetches (OSV + CISA KEV for each)
    per_package_tasks = []
    for pkg in packages:
        per_package_tasks.append(_async_fetch_osv_cves(pkg, ecosystem=ecosystem))
        per_package_tasks.append(_async_fetch_cisa_kev_cves(pkg))

    # Batch-level concurrent fetches (once for all packages)
    batch_tasks = [
        _async_fetch_github_advisories(packages, resolved_versions, ecosystem=ecosystem),
        _async_fetch_deps_dev_cves(packages, resolved_versions, ecosystem=ecosystem),
    ]

    # Run all concurrently with timeout
    try:
        all_results = await asyncio.wait_for(
            asyncio.gather(
                *per_package_tasks,
                *batch_tasks,
                return_exceptions=True
            ),
            timeout=18.0  # 18 second timeout for gather
        )
    except asyncio.TimeoutError:
        # Return empty/timeout results for all tasks
        all_results = [
            ("osv", []) for _ in per_package_tasks[::2]  # One per package
        ] + [
            ("cisa-kev", []) for _ in per_package_tasks[1::2]  # One per package
        ] + [
            ("github-advisories", {"hits": [], "warnings": ["timeout"]}),
            ("deps-dev", {"hits": [], "warnings": ["timeout"]}),
        ]

    # Organize results by package/source
    per_package_results = {}  # {package_name: {source: vulns}}
    batch_results = {}  # {source_name: result}

    # Process per-package results
    for i, pkg in enumerate(packages):
        per_package_results[pkg] = {}

    result_idx = 0
    for pkg in packages:
        osv_result = all_results[result_idx]
        cisa_result = all_results[result_idx + 1]

        if not isinstance(osv_result, Exception):
            source_name, vulns = osv_result
            per_package_results[pkg][source_name] = vulns
        if not isinstance(cisa_result, Exception):
            source_name, vulns = cisa_result
            per_package_results[pkg][source_name] = vulns

        result_idx += 2

    # Process batch results
    for batch_result in all_results[len(per_package_tasks):]:
        if not isinstance(batch_result, Exception):
            source_name, result = batch_result
            batch_results[source_name] = result

    return {
        "per_package": per_package_results,
        "batch": batch_results,
    }


async def _fetch_all_with_timeout(packages, resolved_versions, ecosystem="pypi"):
    """Wrap the concurrent fetch with a hard 20 second timeout."""
    try:
        return await asyncio.wait_for(
            _fetch_all_sources_for_packages_concurrent(packages, resolved_versions, ecosystem=ecosystem),
            timeout=20.0
        )
    except asyncio.TimeoutError:
        return {
            "osv_results": {},
            "cisa_kev_results": {},
            "github_advisories": {"hits": [], "warnings": ["cve sources lookup timeout"]},
            "deps_dev": {"hits": [], "warnings": ["cve sources lookup timeout"]},
        }


def fetch_all_sources_for_packages(
    packages: List[str], resolved_versions: Optional[Dict[str, str]] = None, ecosystem: str = "pypi"
) -> Dict[str, any]:
    """
    Consolidated multi-source lookup: Fetch OSV, CISA KEV, GitHub advisories, and deps.dev
    for all packages concurrently in a single call.

    This eliminates duplicate API calls and is the preferred method for scanner.py.

    Args:
        packages: List of package names to check
        resolved_versions: Dict mapping package names to versions
        ecosystem: depshieldx's internal ecosystem key ("pypi", "npm", ...); translated to
            each source's own naming convention (osv.OSV_ECOSYSTEM_NAMES, GHSA/deps.dev
            equivalents in github_advisories.py/deps_dev.py) since they don't share one
            naming scheme.

    Returns:
        Dict with:
        - 'osv_results': {package: [current_vulns, historical_vulns]}
        - 'cisa_kev_results': {package: [current_vulns, historical_vulns]}
        - 'github_advisories': {hits, warnings} for all packages
        - 'deps_dev': {hits, warnings} for all packages
    """
    try:
        # Run all concurrent fetches with timeout
        all_sources = asyncio.run(_fetch_all_with_timeout(packages, resolved_versions, ecosystem))
    except Exception as e:
        return {
            "osv_results": {},
            "cisa_kev_results": {},
            "github_advisories": {"hits": [], "warnings": [f"cve sources lookup error: {type(e).__name__}"]},
            "deps_dev": {"hits": [], "warnings": [f"cve sources lookup error: {type(e).__name__}"]},
        }

    # Organize per-package results
    osv_results = {}
    cisa_kev_results = {}

    for package_name, sources in all_sources.get("per_package", {}).items():
        osv_vulns = sources.get("osv", [])
        cisa_vulns = sources.get("cisa-kev", [])

        # Categorize by current/historical for OSV
        version = resolved_versions.get(package_name) if resolved_versions else None
        osv_current = []
        osv_historical = []

        if version:
            for vuln in osv_vulns:
                if vuln.is_current_version_vulnerable(version, ecosystem=ecosystem):
                    osv_current.append(vuln.to_dict())
                else:
                    osv_historical.append(vuln.to_dict())
        else:
            osv_current = [v.to_dict() for v in osv_vulns]

        osv_results[package_name] = {
            "current": osv_current,
            "historical": osv_historical,
        }

        # CISA KEV entries matched by product text do not provide reliable PyPI package
        # version ranges, so keep them as non-blocking "unverified" references instead of
        # treating them as current vulnerabilities for the resolved package version.
        cisa_kev_results[package_name] = {
            "current": [],
            "historical": [],
            "unverified": [v.to_dict() for v in cisa_vulns],
        }

    # Extract batch results
    batch_results = all_sources.get("batch", {})
    github_advisories = batch_results.get("github-advisories", {"hits": [], "warnings": []})
    deps_dev = batch_results.get("deps-dev", {"hits": [], "warnings": []})

    return {
        "osv_results": osv_results,
        "cisa_kev_results": cisa_kev_results,
        "github_advisories": github_advisories,
        "deps_dev": deps_dev,
    }
