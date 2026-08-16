from .cve_sources import fetch_all_sources_for_packages

INFO_ONLY_WARNING_PREFIXES = (
    "github advisory lookup unavailable",
    "CISA KEV lookup unavailable",
    "deps.dev lookup unavailable",
)


def _normalize_name(name, ecosystem="pypi"):
    normalized = name.strip().lower()
    if ecosystem == "pypi":
        return normalized.replace("-", "_")
    return normalized


def _split_messages_by_severity(messages):
    warnings = []
    infos = []
    for message in messages:
        if any(message.startswith(prefix) for prefix in INFO_ONLY_WARNING_PREFIXES):
            infos.append(message)
        else:
            warnings.append(message)
    return warnings, infos


def _expand_resolved_versions(packages, resolved_versions=None, ecosystem="pypi"):
    normalized = {
        _normalize_name(name, ecosystem): version
        for name, version in (resolved_versions or {}).items()
        if version
    }
    expanded = {}
    for name, version in (resolved_versions or {}).items():
        if version:
            expanded[name] = version
    for package in packages:
        version = normalized.get(_normalize_name(package, ecosystem))
        if version:
            expanded[package] = version
            expanded[_normalize_name(package, ecosystem)] = version
    return expanded


def scan_vulnerabilities(packages, resolved_versions=None, ecosystem="pypi"):
    """
    Check resolved packages against the four vulnerability sources only:
    OSV, CISA KEV, GitHub Advisories, and deps.dev.
    """
    resolved_lookup = _expand_resolved_versions(packages, resolved_versions, ecosystem)
    all_sources = fetch_all_sources_for_packages(packages, resolved_lookup, ecosystem=ecosystem)

    osv_results = all_sources.get("osv_results", {})
    cisa_kev_results = all_sources.get("cisa_kev_results", {})
    github_result = all_sources.get("github_advisories", {"hits": [], "warnings": []})
    deps_dev_result = all_sources.get("deps_dev", {"hits": [], "warnings": []})

    github_warnings, github_infos = _split_messages_by_severity(github_result.get("warnings", []))
    deps_warnings, deps_infos = _split_messages_by_severity(deps_dev_result.get("warnings", []))
    warnings = list(github_warnings) + list(deps_warnings)
    infos = list(github_infos) + list(deps_infos)

    multi_source_cve_results = {}
    osv_hits = []
    cisa_kev_hits = []
    cisa_kev_unverified_hits = []
    package_versions = {
        package: resolved_lookup.get(package) or resolved_lookup.get(_normalize_name(package, ecosystem)) or ""
        for package in packages
    }

    for pkg in packages:
        pkg_osv = osv_results.get(pkg, {"current": [], "historical": []})
        pkg_cisa = cisa_kev_results.get(pkg, {"current": [], "historical": [], "unverified": []})
        current_vulns = pkg_osv.get("current", []) + pkg_cisa.get("current", [])
        historical_vulns = pkg_osv.get("historical", []) + pkg_cisa.get("historical", [])
        multi_source_cve_results[pkg] = {
            "current": current_vulns,
            "historical": historical_vulns,
            "unverified": pkg_cisa.get("unverified", []),
        }

        for vuln in pkg_osv.get("current", []) + pkg_osv.get("historical", []):
            osv_hits.append(
                {
                    "package": pkg,
                    "package_version": package_versions.get(pkg),
                    "advisory_id": vuln.get("cve_id", ""),
                    "aliases": vuln.get("aliases", []),
                    "summary": vuln.get("summary", ""),
                    "severity": vuln.get("severity", "UNKNOWN"),
                    "source": "osv",
                }
            )
        for vuln in pkg_cisa.get("current", []):
            cisa_kev_hits.append(
                {
                    "package": pkg,
                    "package_version": package_versions.get(pkg),
                    "cve_id": vuln.get("cve_id", ""),
                    "summary": vuln.get("summary", ""),
                    "severity": vuln.get("severity", "HIGH"),
                    "source": "cisa-kev",
                }
            )
        for vuln in pkg_cisa.get("unverified", []):
            cisa_kev_unverified_hits.append(
                {
                    "package": pkg,
                    "package_version": package_versions.get(pkg),
                    "cve_id": vuln.get("cve_id", ""),
                    "summary": vuln.get("summary", ""),
                    "severity": vuln.get("severity", "HIGH"),
                    "source": "cisa-kev",
                }
            )

        if current_vulns:
            cve_ids = [item.get("cve_id") for item in current_vulns[:3] if item.get("cve_id")]
            joined = ", ".join(cve_ids) if cve_ids else "current OSV/CISA vulnerability"
            version = package_versions.get(pkg)
            package_label = f"{pkg}=={version}" if version else pkg
            first_vuln = current_vulns[0] if current_vulns else {}
            return {
                "block": True,
                "reason": f"{package_label} has reported vulnerabilities: {joined}",
                "blocked_package": pkg,
                "blocked_version": version,
                "blocked_source": first_vuln.get("source"),
                "blocked_advisory_id": first_vuln.get("cve_id"),
                "warnings": warnings,
                "infos": infos,
                "threat_intelligence": {
                    "hits": [],
                    "sources": [],
                    "osv": {"hits": osv_hits, "warnings": [], "source": "osv"},
                    "github_advisories": github_result,
                    "cisa_kev": {"hits": cisa_kev_hits, "unverified_hits": cisa_kev_unverified_hits, "warnings": [], "source": "cisa-kev"},
                    "deps_dev": deps_dev_result,
                    "multi_source_cves": multi_source_cve_results,
                    "trivy": None,
                },
            }

    github_hits = github_result.get("hits", [])
    if github_hits:
        first_hit = github_hits[0]
        package_name = first_hit.get("package") or "package"
        version = (
            package_versions.get(package_name)
            or resolved_lookup.get(package_name)
            or resolved_lookup.get(_normalize_name(package_name, ecosystem))
        )
        package_label = f"{package_name}=={version}" if version else package_name
        advisory_id = first_hit.get("ghsa_id") or first_hit.get("cve_id") or "unknown advisory"
        return {
            "block": True,
            "reason": f"{package_label} has GitHub advisory {advisory_id}",
            "blocked_package": package_name,
            "blocked_version": version,
            "blocked_source": "github-advisories",
            "blocked_advisory_id": advisory_id,
            "warnings": warnings,
            "infos": infos,
            "threat_intelligence": {
                "hits": [],
                "sources": [],
                "osv": {"hits": osv_hits, "warnings": [], "source": "osv"},
                "github_advisories": github_result,
                "cisa_kev": {"hits": cisa_kev_hits, "unverified_hits": cisa_kev_unverified_hits, "warnings": [], "source": "cisa-kev"},
                "deps_dev": deps_dev_result,
                "multi_source_cves": multi_source_cve_results,
                "trivy": None,
            },
        }

    deps_hits = deps_dev_result.get("hits", [])
    for hit in deps_hits:
        if hit.get("advisory_count", 0) <= 0:
            continue
        package_name = hit.get("package") or "package"
        version = hit.get("package_version") or package_versions.get(package_name)
        package_label = f"{package_name}=={version}" if version else package_name
        advisory_ids = [item.get("id") for item in hit.get("advisories", []) if item.get("id")]
        suffix = f": {', '.join(advisory_ids[:3])}" if advisory_ids else ""
        return {
            "block": True,
            "reason": f"{package_label} has deps.dev advisory reference(s){suffix}",
            "blocked_package": package_name,
            "blocked_version": version,
            "blocked_source": "deps-dev",
            "blocked_advisory_id": advisory_ids[0] if advisory_ids else None,
            "warnings": warnings,
            "infos": infos,
            "threat_intelligence": {
                "hits": [],
                "sources": [],
                "osv": {"hits": osv_hits, "warnings": [], "source": "osv"},
                "github_advisories": github_result,
                "cisa_kev": {"hits": cisa_kev_hits, "unverified_hits": cisa_kev_unverified_hits, "warnings": [], "source": "cisa-kev"},
                "deps_dev": deps_dev_result,
                "multi_source_cves": multi_source_cve_results,
                "trivy": None,
            },
        }

    return {
        "block": False,
        "warnings": warnings,
        "infos": infos,
        "threat_intelligence": {
            "hits": [],
            "sources": [],
            "osv": {"hits": osv_hits, "warnings": [], "source": "osv"},
            "github_advisories": github_result,
            "cisa_kev": {"hits": cisa_kev_hits, "unverified_hits": cisa_kev_unverified_hits, "warnings": [], "source": "cisa-kev"},
            "deps_dev": deps_dev_result,
            "multi_source_cves": multi_source_cve_results,
            "trivy": None,
        },
    }
