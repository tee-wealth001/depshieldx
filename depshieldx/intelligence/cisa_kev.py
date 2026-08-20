"""CISA KEV (Known Exploited Vulnerabilities) source client.

Two independent, non-consolidated implementations live here, moved verbatim
from where they previously lived (cve_sources.py and threat_intel.py
respectively) -- they solve different sub-problems and were never actually
the same code, just the same upstream feed:

- _async_fetch_cisa_kev_cves(_inner): the live one, on scanner.py's actual
  path via intelligence/orchestrator.py. Takes a package name and matches it
  against each KEV entry's free-text "product" field via a regex heuristic.
- fetch_cisa_kev: only reachable from tests today, not from the live scan
  path. Takes a list of already-known CVE IDs and checks each for an exact
  match in the KEV list.

Consolidating these is a real functional decision, not a restructuring one
-- left as a known, pre-existing gap for a future pass.
"""

from typing import Dict, Iterable, List, Tuple

import aiohttp
import re
import requests

from .common import MAX_RETRIES, REQUEST_TIMEOUT, _async_retry
from .models import VersionVulnerability

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def _async_fetch_cisa_kev_cves_inner(session: aiohttp.ClientSession, package_name: str) -> List[VersionVulnerability]:
    """Inner function for CISA KEV fetch (without session management for retries)."""
    vulns = []

    async with session.get(
        CISA_KEV_URL,
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


async def _async_fetch_cisa_kev_cves(package_name: str) -> Tuple[str, List[VersionVulnerability], List[str]]:
    """Async: Fetch from CISA KEV with retry logic.

    CISA KEV is a blocking source (see scanner.py) -- a silently swallowed
    exception here previously made a real lookup failure indistinguishable
    from "checked CISA KEV, found nothing." The third return element
    surfaces that failure as a warning instead, using the same "CISA KEV
    lookup unavailable" message prefix fetch_cisa_kev already uses (and
    scanner.py's INFO_ONLY_WARNING_PREFIXES already recognizes), so it's
    now actually produced on this live async path too.
    """
    vulns = []
    warnings: List[str] = []
    try:
        async with aiohttp.ClientSession() as session:
            vulns = await _async_retry(
                _async_fetch_cisa_kev_cves_inner,
                session,
                package_name,
                max_retries=MAX_RETRIES,
            )
    except Exception as e:
        warnings.append(f"CISA KEV lookup unavailable for {package_name}: {e}")
    return "cisa-kev", vulns, warnings


def fetch_cisa_kev(cve_ids: Iterable[str]) -> dict:
    normalized_cves = sorted({cve_id for cve_id in cve_ids if cve_id})
    if not normalized_cves:
        return {"hits": [], "warnings": [], "source": "cisa_kev"}

    try:
        response = requests.get(CISA_KEV_URL, timeout=4)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        return {
            "hits": [],
            "warnings": [f"CISA KEV lookup unavailable: {exc}"],
            "source": "cisa_kev",
        }

    kev_by_cve = {
        item.get("cveID"): item
        for item in payload.get("vulnerabilities", [])
        if item.get("cveID")
    }
    hits = []
    for cve_id in normalized_cves:
        match = kev_by_cve.get(cve_id)
        if not match:
            continue
        hits.append(
            {
                "cve_id": cve_id,
                "vendor_project": match.get("vendorProject"),
                "product": match.get("product"),
                "vulnerability_name": match.get("vulnerabilityName"),
                "date_added": match.get("dateAdded"),
                "known_ransomware": match.get("knownRansomwareCampaignUse"),
                "source": "cisa_kev",
            }
        )

    return {"hits": hits, "warnings": [], "source": "cisa_kev"}
