import json
import os
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import quote, urlparse

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
import requests


DEFAULT_FEED_ENV = "DEPSHIELDX_THREAT_FEEDS"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEPS_DEV_VERSION_URLS = (
    "https://api.deps.dev/v3/systems/pypi/packages/{package}/versions/{version}",
    "https://api.deps.dev/v3alpha/systems/pypi/packages/{package}/versions/{version}",
)


def _normalize_name(name: str) -> str:
    return name.strip().lower().replace("-", "_")


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


def _is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _iter_feed_locations(feed_locations: Iterable[str] | None) -> list[str]:
    configured = list(feed_locations or [])
    env_value = os.environ.get(DEFAULT_FEED_ENV, "").strip()
    if env_value:
        configured.extend(part.strip() for part in env_value.split(",") if part.strip())
    return configured


def _load_feed_document(location: str) -> tuple[dict | None, str | None]:
    try:
        if _is_url(location):
            response = requests.get(location, timeout=3)
            response.raise_for_status()
            return response.json(), None
        return json.loads(Path(location).read_text()), None
    except Exception as exc:
        return None, f"{location}: {exc}"


def _deps_dev_version_payload(package: str, version: str) -> tuple[dict | None, str | None]:
    encoded_package = quote(package, safe="")
    encoded_version = quote(version, safe="")
    last_error = None
    for template in DEPS_DEV_VERSION_URLS:
        try:
            response = requests.get(
                template.format(package=encoded_package, version=encoded_version),
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


def _parse_package_entries(source: str, payload: dict) -> list[dict]:
    entries = []
    for package_name, metadata in (payload.get("packages") or {}).items():
        metadata = metadata or {}
        aliases = [_normalize_name(alias) for alias in metadata.get("aliases", [])]
        entries.append(
            {
                "type": "package",
                "value": _normalize_name(package_name),
                "aliases": aliases,
                "severity": metadata.get("severity", "block"),
                "reason": metadata.get("reason", "known malicious package"),
                "source": source,
            }
        )
    return entries


def _parse_pattern_entries(source: str, payload: dict) -> list[dict]:
    entries = []
    for record in payload.get("patterns", []):
        pattern = (record or {}).get("pattern")
        if not pattern:
            continue
        entries.append(
            {
                "type": "pattern",
                "value": pattern,
                "severity": record.get("severity", "warn"),
                "reason": record.get("reason", "matches threat-intelligence indicator"),
                "source": source,
            }
        )
    return entries


def _load_feed_entries(feed_locations: Iterable[str] | None = None) -> dict:
    entries = []
    warnings = []
    sources = []

    for location in _iter_feed_locations(feed_locations):
        payload, error = _load_feed_document(location)
        if error:
            warnings.append(f"threat intelligence feed unavailable: {error}")
            continue
        if not isinstance(payload, dict):
            warnings.append(f"threat intelligence feed invalid: {location}")
            continue
        entries.extend(_parse_package_entries(location, payload))
        entries.extend(_parse_pattern_entries(location, payload))
        sources.append(location)

    return {
        "entries": entries,
        "sources": sources,
        "warnings": warnings,
    }


def check_threat_intelligence(packages: list[str], feed_locations: Iterable[str] | None = None) -> dict:
    feed = _load_feed_entries(feed_locations)
    hits = []
    warnings = list(feed["warnings"])

    for package_name in packages:
        normalized_name = _normalize_name(package_name)
        for entry in feed["entries"]:
            if entry["type"] == "package":
                aliases = set(entry.get("aliases", []))
                matched = normalized_name == entry["value"] or normalized_name in aliases
            else:
                matched = re.search(entry["value"], normalized_name) is not None
            if not matched:
                continue

            hit = {
                "package": package_name,
                "matched_on": entry["type"],
                "indicator": entry["value"],
                "severity": entry["severity"],
                "reason": entry["reason"],
                "source": entry["source"],
            }
            hits.append(hit)
            if entry["severity"] == "block":
                return {
                    "block": True,
                    "reason": f"{package_name} matched threat-intelligence feed: {entry['reason']}",
                    "hits": hits,
                    "warnings": warnings,
                    "sources": feed["sources"],
                }
            warnings.append(f"{package_name} threat-intelligence warning: {entry['reason']}")

    return {
        "block": False,
        "reason": None,
        "hits": hits,
        "warnings": warnings,
        "sources": feed["sources"],
    }


def fetch_github_advisories(packages: list[str], resolved_versions: dict[str, str] | None = None) -> dict:
    normalized_packages = sorted({_normalize_name(package) for package in packages if package})
    resolved_versions = {
        _normalize_name(name): version
        for name, version in (resolved_versions or {}).items()
        if version
    }
    if not normalized_packages:
        return {"hits": [], "warnings": [], "source": "github_advisories"}

    try:
        response = requests.get(
            GITHUB_ADVISORIES_URL,
            params={
                "ecosystem": "pip",
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
            package = _normalize_name(vulnerability.get("package", {}).get("name", ""))
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


def fetch_deps_dev_insights(packages: list[str], resolved_versions: dict[str, str] | None = None) -> dict:
    normalized_versions = {
        _normalize_name(name): version
        for name, version in (resolved_versions or {}).items()
        if version
    }
    hits = []
    warnings = []

    for package in packages:
        normalized_name = _normalize_name(package)
        version = normalized_versions.get(normalized_name)
        if not version:
            continue

        payload, error = _deps_dev_version_payload(normalized_name, version)
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
