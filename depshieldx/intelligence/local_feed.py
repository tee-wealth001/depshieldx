"""Local/URL JSON threat-feed checker.

Not one of the four external CVE sources (OSV/GHSA/deps.dev/CISA KEV) --
a separate feature that checks resolved packages against a local or
remote JSON feed of known-malicious packages/patterns, configured via
DEPSHIELDX_THREAT_FEEDS. Not wired into any live scan path today (no
caller in scanner.py or elsewhere in depshieldx/), but has real test
coverage exercising real logic, so it's preserved as-is rather than
dropped during this restructuring.
"""

import json
import os
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import requests

from .common import _normalize_name

DEFAULT_FEED_ENV = "DEPSHIELDX_THREAT_FEEDS"


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
