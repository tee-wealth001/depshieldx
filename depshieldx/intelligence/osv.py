"""OSV (https://osv.dev) vulnerability source client."""

from typing import List, Tuple

import aiohttp

from .common import MAX_RETRIES, REQUEST_TIMEOUT, _async_retry
from .models import VersionVulnerability

# depshieldx's internal ecosystem key -> OSV's own ecosystem enum value.
# https://ossf.github.io/osv-schema/#affectedpackage-field
OSV_ECOSYSTEM_NAMES = {
    "pypi": "PyPI",
    "npm": "npm",
}


async def _async_fetch_osv_cves_inner(
    session: aiohttp.ClientSession, package_name: str, ecosystem: str = "pypi"
) -> List[VersionVulnerability]:
    """Inner function for OSV fetch (without session management for retries)."""
    vulns = []
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package_name, "ecosystem": OSV_ECOSYSTEM_NAMES.get(ecosystem, "PyPI")},
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


async def _async_fetch_osv_cves(package_name: str, ecosystem: str = "pypi") -> Tuple[str, List[VersionVulnerability]]:
    """Async: Fetch CVEs from OSV with retry logic."""
    vulns = []
    try:
        async with aiohttp.ClientSession() as session:
            vulns = await _async_retry(
                _async_fetch_osv_cves_inner,
                session,
                package_name,
                ecosystem=ecosystem,
                max_retries=MAX_RETRIES,
            )
    except Exception as e:
        pass
    return "osv", vulns
