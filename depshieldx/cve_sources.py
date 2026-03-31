"""
Multi-source CVE lookup module.

Queries multiple free vulnerability databases concurrently:
- OSV (covers NVD, GitHub, etc.)
- CISA KEV (Known Exploited Vulnerabilities)
- deps.dev (Dependency insights and advisories)
- GitHub Advisories (Package security advisories)
"""

import asyncio
import json
import re
import time
from typing import Optional, Dict, List, Tuple
from urllib.parse import quote, urljoin
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet
import aiohttp
import requests

# Source names for reporting
SOURCES = {
    "osv": "https://api.osv.dev",
    "snyk": "https://snyk.io",
    "cisa-kev": "https://www.cisa.gov",
    "deps_dev": "https://api.deps.dev/v3",
}

# Increased timeout for better resilience on slower networks
REQUEST_TIMEOUT = 10

# Retry configuration for transient failures
MAX_RETRIES = 3
INITIAL_BACKOFF = 1  # seconds


async def _async_retry(
    coro_fn,
    *args,
    max_retries: int = MAX_RETRIES,
    initial_backoff: float = INITIAL_BACKOFF,
    **kwargs
):
    """
    Retry a coroutine with exponential backoff on transient failures.
    
    Retries on: timeout, connection errors, and 5xx server errors.
    Returns the result or raises exception after max retries.
    """
    backoff = initial_backoff
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return await coro_fn(*args, **kwargs)
        except (asyncio.TimeoutError, aiohttp.ClientConnectorError, aiohttp.ClientSSLError) as e:
            # Transient network errors - retry
            last_exception = e
            if attempt < max_retries - 1:
                await asyncio.sleep(backoff)
                backoff *= 2  # Exponential backoff
        except Exception as e:
            # Other errors - don't retry
            raise
    
    # All retries exhausted
    if last_exception:
        raise last_exception


class VersionVulnerability:
    """Represents a vulnerability with version-specific information."""

    def __init__(
        self,
        cve_id: str,
        source: str,
        affected_versions: Optional[List[str]] = None,
        fixed_in_version: Optional[str] = None,
        severity: str = "UNKNOWN",
        summary: str = "",
        aliases: Optional[List[str]] = None,
    ):
        self.cve_id = cve_id
        self.source = source
        self.affected_versions = affected_versions or []
        self.fixed_in_version = fixed_in_version
        self.severity = severity
        self.summary = summary
        self.aliases = aliases or []

    def is_current_version_vulnerable(self, version: str) -> bool:
        """Check if a specific version is affected by this vulnerability."""
        if not self.affected_versions and not self.fixed_in_version:
            return True  # Unknown range, assume vulnerable

        try:
            check_version = Version(version)
        except InvalidVersion:
            return True

        # Check affected versions list
        for affected_range in self.affected_versions:
            try:
                spec_set = SpecifierSet(affected_range)
                if check_version in spec_set:
                    return True
            except Exception:
                pass

        # Check if version is before fix
        if self.fixed_in_version:
            try:
                fixed_version = Version(self.fixed_in_version)
                if check_version < fixed_version:
                    return True
            except InvalidVersion:
                pass

        return False

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "source": self.source,
            "affected_versions": self.affected_versions,
            "fixed_in_version": self.fixed_in_version,
            "severity": self.severity,
            "summary": self.summary,
            "aliases": self.aliases,
        }


def _fetch_nvd_cves(package_name: str) -> List[VersionVulnerability]:
    """Fetch CVEs from NVD via OSV integration."""
    return []


async def _async_fetch_osv_cves_inner(session: aiohttp.ClientSession, package_name: str) -> List[VersionVulnerability]:
    """Inner function for OSV fetch (without session management for retries)."""
    vulns = []
    # OSV API query for Python packages
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package_name, "ecosystem": "PyPI"},
    }
    
    async with session.post(
        url,
        json=payload,
        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        headers={"Content-Type": "application/json"},
    ) as response:
        if response.status == 200:
            data = await response.json()
            for vuln_item in data.get("vulns", []):
                vuln_id = vuln_item.get("id", "")
                
                # Try to get CVE ID from aliases
                cve_id = None
                for alias in vuln_item.get("aliases", []):
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break
                if not cve_id:
                    cve_id = vuln_id  # Use OSV ID if no CVE
                
                affected_versions = []
                fixed_version = None
                
                # Extract affected version ranges from OSV format
                for affected in vuln_item.get("affected", []):
                    if affected.get("package", {}).get("name", "").lower() == package_name.lower():
                        versions = affected.get("versions", [])
                        ranges = affected.get("ranges", [])
                        
                        # Process ranges first - if we have good ranges, prefer them over individual versions
                        range_specs = []
                        for range_item in ranges:
                            range_type = range_item.get("type", "")
                            events = range_item.get("events", [])
                            
                            # Find introduced and fixed versions
                            introduced = None
                            fixed = None
                            last_affected = None
                            
                            for event in events:
                                if "introduced" in event:
                                    introduced = event.get("introduced")
                                if "fixed" in event:
                                    fixed = event.get("fixed")
                                if "last_affected" in event:
                                    last_affected = event.get("last_affected")
                            
                            # Build PEP 440 spec string
                            # Only create specs for ranges that have both introduced AND a bound (fixed/last_affected)
                            try:
                                if introduced and fixed:
                                    # For "fixed" versions, use < (not including the fixed version)
                                    spec = f">={introduced},<{fixed}"
                                    range_specs.append(spec)
                                    if not fixed_version:
                                        fixed_version = fixed
                                elif introduced and last_affected:
                                    # For "last_affected", use <= (versions up to and including last affected)
                                    spec = f">={introduced},<={last_affected}"
                                    range_specs.append(spec)
                                    if not fixed_version:
                                        fixed_version = last_affected
                                elif fixed and not introduced:
                                    #Only "fixed" without introduced - affected versions < fixed
                                    spec = f"<{fixed}"
                                    range_specs.append(spec)
                                    if not fixed_version:
                                        fixed_version = fixed
                                elif last_affected and not introduced:
                                    # Only "last_affected" without introduced
                                    spec = f"<={last_affected}"
                                    range_specs.append(spec)
                                # SKIP ranges with only "introduced" - they're incomplete and would match everything
                            except Exception:
                                pass  # Skip ranges that fail to parse
                        
                        # If we have complete ranges (with bounds), use those instead of individual versions
                        if range_specs:
                            affected_versions.extend(range_specs)
                        else:
                            # Fall back to individual versions only if no ranges available
                            for v in versions:
                                affected_versions.append(f"=={v}")
                
                # Create vulnerability record
                severity = vuln_item.get("database_specific", {}).get("severity", "UNKNOWN")
                aliases = vuln_item.get("aliases", [])
                
                vuln = VersionVulnerability(
                    cve_id=cve_id,
                    source="osv",
                    affected_versions=affected_versions if affected_versions else [],
                    fixed_in_version=fixed_version,
                    severity=severity,
                    summary=vuln_item.get("summary", ""),
                    aliases=aliases,
                )
                vulns.append(vuln)
    return vulns


async def _async_fetch_osv_cves(package_name: str) -> Tuple[str, List[VersionVulnerability]]:
    """Async: Fetch CVEs from OSV with retry logic."""
    vulns = []
    try:
        async with aiohttp.ClientSession() as session:
            vulns = await _async_retry(
                _async_fetch_osv_cves_inner,
                session,
                package_name,
                max_retries=MAX_RETRIES,
            )
    except Exception as e:
        pass
    return "osv", vulns


async def _async_fetch_cisa_kev_cves_inner(session: aiohttp.ClientSession, package_name: str) -> List[VersionVulnerability]:
    """Inner function for CISA KEV fetch (without session management for retries)."""
    vulns = []
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    async with session.get(
        url,
        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
    ) as response:
        if response.status == 200:
            data = await response.json()
            for vuln_item in data.get("vulnerabilities", []):
                product = (vuln_item.get("product") or "").lower().replace("_", "-")
                normalized_name = package_name.lower().replace("_", "-")
                if re.search(rf"(?<![a-z0-9]){re.escape(normalized_name)}(?![a-z0-9])", product):
                    cve_id = vuln_item.get("cveID", "")
                    if cve_id:
                        vuln = VersionVulnerability(
                            cve_id=cve_id,
                            source="cisa-kev",
                            severity="HIGH",  # CISA KEV are typically high priority
                            summary=vuln_item.get("shortDescription", ""),
                        )
                        vulns.append(vuln)
    return vulns


async def _async_fetch_cisa_kev_cves(package_name: str) -> Tuple[str, List[VersionVulnerability]]:
    """Async: Fetch from CISA KEV with retry logic."""
    vulns = []
    try:
        async with aiohttp.ClientSession() as session:
            vulns = await _async_retry(
                _async_fetch_cisa_kev_cves_inner,
                session,
                package_name,
                max_retries=MAX_RETRIES,
            )
    except Exception as e:
        pass
    return "cisa-kev", vulns


async def _async_fetch_deps_dev_cves(packages: List[str], resolved_versions: Optional[Dict[str, str]] = None) -> Tuple[str, Dict]:
    """Async wrapper: Fetch insights from deps.dev with timeout protection."""
    try:
        # Import here to avoid circular import
        from .threat_intel import fetch_deps_dev_insights
        loop = asyncio.get_event_loop()
        # Use lambda to properly pass keyword arguments through executor
        result = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: fetch_deps_dev_insights(packages, resolved_versions=resolved_versions)
            ),
            timeout=15.0  # 15 second timeout
        )
        return "deps-dev", result
    except asyncio.TimeoutError:
        return "deps-dev", {"hits": [], "warnings": ["deps.dev lookup unavailable: timeout"]}
    except Exception:
        return "deps-dev", {"hits": [], "warnings": ["deps.dev lookup unavailable"]}


async def _async_fetch_github_advisories(packages: List[str], resolved_versions: Optional[Dict[str, str]] = None) -> Tuple[str, Dict]:
    """Async wrapper: Fetch GitHub Security Advisories with timeout protection."""
    try:
        # Import here to avoid circular import
        from .threat_intel import fetch_github_advisories
        loop = asyncio.get_event_loop()
        # Use lambda to properly pass keyword arguments through executor
        result = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: fetch_github_advisories(packages, resolved_versions=resolved_versions)
            ),
            timeout=15.0  # 15 second timeout
        )
        return "github-advisories", result
    except asyncio.TimeoutError:
        return "github-advisories", {"hits": [], "warnings": ["GitHub advisory lookup unavailable: timeout"]}
    except Exception:
        return "github-advisories", {"hits": [], "warnings": ["GitHub advisory lookup unavailable"]}


async def _fetch_all_sources_concurrent(package_name: str) -> Dict[str, List]:
    """Fetch from all sources concurrently."""
    tasks = [
        _async_fetch_osv_cves(package_name),
        _async_fetch_cisa_kev_cves(package_name),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    sources_data = {}

    for result in results:
        if isinstance(result, Exception):
            continue
        source_name, vulns = result
        sources_data[source_name] = vulns

    return sources_data


async def _fetch_all_sources_for_packages_concurrent(
    packages: List[str], resolved_versions: Optional[Dict[str, str]] = None
) -> Dict[str, any]:
    """
    Fetch from all sources concurrently for multiple packages.
    Handles both per-package (OSV, CISA KEV) and batch-level (GitHub, deps.dev) fetches.
    """
    tasks = []
    
    # Per-package concurrent fetches (OSV + CISA KEV for each)
    per_package_tasks = []
    for pkg in packages:
        per_package_tasks.append(_async_fetch_osv_cves(pkg))
        per_package_tasks.append(_async_fetch_cisa_kev_cves(pkg))
    
    # Batch-level concurrent fetches (once for all packages)
    batch_tasks = [
        _async_fetch_github_advisories(packages, resolved_versions),
        _async_fetch_deps_dev_cves(packages, resolved_versions),
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


def fetch_cves_from_all_sources(
    package_name: str, version: Optional[str] = None
) -> Dict[str, Dict]:
    """
    Fetch CVEs from multiple sources for a package (concurrent execution).

    Returns a dict with:
    - 'current_vulns': vulns affecting the specified version
    - 'historical_vulns': vulns that affected older versions
    - 'sources': results from each source
    """
    # Run concurrent fetches
    try:
        sources_data = asyncio.run(_fetch_all_sources_concurrent(package_name))
    except Exception as e:
        sources_data = {}

    sources_results = {}
    current_vulns = []
    historical_vulns = []

    # Process results from each source
    for source_name, vulns_list in sources_data.items():
        sources_results[source_name] = {
            "vulns": [v.to_dict() for v in vulns_list],
            "count": len(vulns_list),
        }

        # If version provided, categorize vulns
        if version:
            for vuln in vulns_list:
                if vuln.is_current_version_vulnerable(version):
                    current_vulns.append(vuln)
                else:
                    historical_vulns.append(vuln)
        else:
            current_vulns.extend(vulns_list)

    return {
        "package": package_name,
        "version": version,
        "current_vulns": [v.to_dict() for v in current_vulns],
        "historical_vulns": [v.to_dict() for v in historical_vulns],
        "sources": sources_results,
    }


def block_on_current_vulns(package_name: str, version: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a package version should be blocked due to current vulnerabilities.

    Returns (should_block, reason)
    """
    result = fetch_cves_from_all_sources(package_name, version)

    if result["current_vulns"]:
        vuln_count = len(result["current_vulns"])
        vuln_id = result["current_vulns"][0]["cve_id"]
        return True, f"{package_name} has {vuln_count} current vulnerability/ies ({vuln_id})"

    return False, None


def check_dependencies_for_vulns(
    dependencies: Dict[str, str],
) -> Tuple[bool, List[str]]:
    """
    Check dependencies for vulnerabilities.

    Returns (any_blocked, list of blocking reasons)
    """
    blocking_reasons = []
    warning_reasons = []

    for dep_name, dep_version in dependencies.items():
        should_block, reason = block_on_current_vulns(dep_name, dep_version)
        if should_block:
            blocking_reasons.append(reason)

    return len(blocking_reasons) > 0, blocking_reasons


def check_all_with_dependency_context(
    main_package: str,
    main_version: str,
    dependencies: Dict[str, str],
) -> Dict:
    """
    Check main package and its dependencies with clear distinction.

    Returns a comprehensive report with:
    - main_package_vulns: vulnerabilities in the main package
    - dependency_vulns: vulnerabilities in dependencies
    - blocking_issues: any CVEs requiring blocking
    - warnings: historical vulnerabilities in dependencies
    """
    result = {
        "main_package": main_package,
        "main_version": main_version,
        "main_vulns": {
            "current": [],
            "historical": [],
        },
        "dependency_checks": {},
        "blocking_issues": [],
        "warnings": [],
    }

    # Check main package
    main_result = fetch_cves_from_all_sources(main_package, main_version)
    result["main_vulns"]["current"] = main_result.get("current_vulns", [])
    result["main_vulns"]["historical"] = main_result.get("historical_vulns", [])

    if result["main_vulns"]["current"]:
        for vuln in result["main_vulns"]["current"]:
            result["blocking_issues"].append(
                f"Main package {main_package}=={main_version} has current vulnerability: {vuln.get('cve_id')}"
            )

    # Check dependencies
    for dep_name, dep_version in dependencies.items():
        dep_result = fetch_cves_from_all_sources(dep_name, dep_version)
        result["dependency_checks"][dep_name] = {
            "version": dep_version,
            "current": dep_result.get("current_vulns", []),
            "historical": dep_result.get("historical_vulns", []),
        }

        # Block if dependency has current vulnerabilities
        if dep_result.get("current_vulns"):
            for vuln in dep_result["current_vulns"]:
                result["blocking_issues"].append(
                    f"Dependency {dep_name}=={dep_version} has current vulnerability: {vuln.get('cve_id')}"
                )

        # Warn if dependency has historical vulnerabilities
        if dep_result.get("historical_vulns"):
            for vuln in dep_result["historical_vulns"][:2]:  # Show first 2
                result["warnings"].append(
                    f"Dependency {dep_name} previously had vulnerability {vuln.get('cve_id')} (fixed in newer version)"
                )

    return result


async def _fetch_all_with_timeout(packages, resolved_versions):
    """Wrap the concurrent fetch with a hard 20 second timeout."""
    try:
        return await asyncio.wait_for(
            _fetch_all_sources_for_packages_concurrent(packages, resolved_versions),
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
    packages: List[str], resolved_versions: Optional[Dict[str, str]] = None
) -> Dict[str, any]:
    """
    Consolidated multi-source lookup: Fetch OSV, CISA KEV, GitHub advisories, and deps.dev
    for all packages concurrently in a single call.
    
    This eliminates duplicate API calls and is the preferred method for scanner.py.
    
    Args:
        packages: List of package names to check
        resolved_versions: Dict mapping package names to versions
    
    Returns:
        Dict with:
        - 'osv_results': {package: [current_vulns, historical_vulns]}
        - 'cisa_kev_results': {package: [current_vulns, historical_vulns]}
        - 'github_advisories': {hits, warnings} for all packages
        - 'deps_dev': {hits, warnings} for all packages
    """
    try:
        # Run all concurrent fetches with timeout
        all_sources = asyncio.run(_fetch_all_with_timeout(packages, resolved_versions))
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
                if vuln.is_current_version_vulnerable(version):
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
