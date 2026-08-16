"""Human-summary formatting, JSON rendering, and process-exit handling.

Also owns the _JSON_ONLY_OUTPUT flag: when set, progress/stage messages go
to stderr instead of stdout, so stdout stays pure JSON for `--output json`
(final-plan.md Phase 0's "no human text mixed in" rule). A bare module
global can't be set correctly from install/scan (which live in separate
files, commands/install.py and commands/scan.py, after this package split)
-- Python's `global` statement only rebinds the current module's own
namespace, so those commands doing `global _JSON_ONLY_OUTPUT` after
importing it from here would silently create a disconnected copy rather
than mutating this one. set_json_only_output() is the fix: commands call
the setter instead of assigning to an imported name directly.
"""

import json
import re
import sys
import threading
from contextlib import contextmanager
from urllib.parse import quote

import click

from .report import _prepare_report_with_receipt

EXIT_OK = 0
EXIT_BLOCKED = 10
EXIT_SANDBOX_UNAVAILABLE = 11
EXIT_INSTALL_FAILED = 12

_output_state = {"json_only": False}


def set_json_only_output(value: bool) -> None:
    _output_state["json_only"] = value


def _progress_stream():
    return sys.stderr if _output_state["json_only"] else sys.stdout


def _echo_step(message):
    click.echo(message, file=_progress_stream())


def _echo_success(message):
    click.secho(message, fg="green", file=_progress_stream())


def _echo_error(message):
    click.secho(message, fg="red", file=_progress_stream())


def _write_stage_frame(message, suffix, *, newline=False):
    stream = _progress_stream()
    line = f"\r\033[2K{message} {suffix}"
    if newline:
        line += "\n"
    stream.write(line)
    stream.flush()


@contextmanager
def _stage_loader(message, *, verbose=False, animated=True):
    if verbose or not _progress_stream().isatty() or not animated:
        _echo_step(message)
        try:
            yield
        except BaseException:
            _echo_step(f"{message} failed")
            raise
        _echo_step(f"{message} done")
        return

    stop_event = threading.Event()
    frames = ["|", "/", "-", "\\"]
    status = {"suffix": "done"}

    def _spin():
        index = 0
        while not stop_event.is_set():
            _write_stage_frame(message, frames[index % len(frames)])
            index += 1
            stop_event.wait(0.1)
        _write_stage_frame(message, status["suffix"], newline=True)

    spinner = threading.Thread(target=_spin, daemon=True)
    spinner.start()
    try:
        yield
    except BaseException:
        status["suffix"] = "failed"
        raise
    finally:
        stop_event.set()
        spinner.join()


def _verdict_summary(label, result):
    warning_count = len(result.get("warnings") or [])
    info_count = len(result.get("infos") or [])
    return f"{label}: passed with {warning_count} warning(s), {info_count} info item(s)"


def _emit_message_group(label, messages, color):
    if not messages:
        return
    stream = _progress_stream()
    click.secho(f"{label}:", fg=color, file=stream)
    for message in messages:
        click.secho(f"  - {message}", fg=color, file=stream)


def _emit_result_messages(label, result):
    _emit_message_group(f"{label} Warnings", result.get("warnings", []), "yellow")
    _emit_message_group(f"{label} Info", result.get("infos", []), "blue")


def _receipt_count_label(count):
    return f"{count} package receipt" if count == 1 else f"{count} package receipts"


def _summary_line_color(line):
    if line.startswith("Runtime prerequisites: satisfied"):
        return "green"
    if line.startswith("Runtime prerequisites: blocked"):
        return "red"
    if line.startswith("Host install: succeeded"):
        return "green"
    if line.startswith("Host install: failed") or line.startswith("Host install: blocked"):
        return "red"
    if line.startswith("Host install: skipped"):
        return "blue"

    if "blocked (" in line or line.endswith(": failed"):
        if line.startswith(("Scan verdict:", "Provenance verdict:", "Policy verdict:", "Sandbox verdict:")):
            return "red"

    if line.startswith(("Scan verdict:", "Provenance verdict:", "Policy verdict:")):
        match = re.search(r"passed with (\d+) warning\(s\), (\d+) info item\(s\)", line)
        if match:
            warning_count = int(match.group(1))
            info_count = int(match.group(2))
            if warning_count > 0:
                return "yellow"
            if info_count > 0:
                return "blue"
            return "green"

    if line.startswith("Sandbox verdict: passed"):
        return "green"
    if line.startswith("Trivy verdict: passed"):
        return "green"
    if line.startswith("Trivy verdict: blocked"):
        return "red"
    if line.startswith("Trivy verdict: unavailable"):
        return "blue"
    if line.startswith("Attestation infrastructure issue:"):
        return "blue"
    if line.startswith(("First policy warning:", "First sandbox warning:")):
        return "yellow"
    if line.startswith("First Trivy warning:"):
        return "yellow"
    if line.startswith(
        (
            "First policy info:",
            "First sandbox info:",
            "Sandbox trust:",
            "Receipt:",
            "Receipts:",
            "Receipt ID:",
            "Receipt path:",
            "PyPI project links:",
        )
    ):
        return "blue"
    if line.startswith("  - ") and "https://pypi.org/project/" in line:
        return "blue"
    if line.startswith(("First attestation failure:", "First blocked event:", "First import failure:", "First Trivy finding:")):
        return "red"
    return None


def _pypi_project_url_for_target(target):
    if not target or "," in target:
        return None

    value = target.strip()
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([A-Za-z0-9_.!+-]+)$", value)
    if not match:
        return None

    package_name, version = match.groups()
    return f"https://pypi.org/project/{quote(package_name)}/{quote(version)}/"


def _package_name_from_requirement(target):
    if not target:
        return None
    value = target.strip()
    if not value or value.startswith(("-", ".", "/", "~")) or "://" in value or "/" in value or "\\" in value:
        return None
    match = re.match(r"^([A-Za-z0-9_.-]+)", value)
    return match.group(1) if match else None


def _pypi_project_links(report):
    resolution = report.get("resolution") or {}
    requested_targets = resolution.get("requested_targets") or []
    resolved_versions = resolution.get("resolved_versions") or {}
    resolved_lookup = {
        name.strip().lower().replace("-", "_"): (name, version)
        for name, version in resolved_versions.items()
        if version
    }

    links = []
    seen = set()
    for target in requested_targets:
        requested_name = _package_name_from_requirement(target)
        if not requested_name:
            continue
        resolved = resolved_lookup.get(requested_name.lower().replace("-", "_"))
        if not resolved:
            continue
        package_name, version = resolved
        key = (package_name, version)
        if key in seen:
            continue
        seen.add(key)
        links.append(
            f"{package_name}=={version} ({_pypi_project_url_for_target(f'{package_name}=={version}')})"
        )
    return links


def _resolved_requested_packages(resolution):
    requested_targets = resolution.get("requested_targets") or []
    resolved_versions = resolution.get("resolved_versions") or {}
    resolved_lookup = {
        name.strip().lower().replace("-", "_"): (name, version)
        for name, version in resolved_versions.items()
        if version
    }

    requested_packages = []
    seen = set()
    for target in requested_targets:
        requested_name = _package_name_from_requirement(target)
        if not requested_name:
            continue
        resolved = resolved_lookup.get(requested_name.lower().replace("-", "_"))
        if not resolved:
            continue
        key = (resolved[0], resolved[1])
        if key in seen:
            continue
        seen.add(key)
        requested_packages.append(key)
    return requested_packages


def _format_cve_source_lines(source_data):
    lines = []
    for source in sorted(source_data.keys()):
        current_count = source_data[source].get("current", 0)
        historical_count = source_data[source].get("historical", 0)
        unverified_count = source_data[source].get("unverified", 0)
        if source == "deps-dev" and source_data[source].get("checked_records", 0) > 0:
            checked_records = source_data[source]["checked_records"]
            advisory_references = source_data[source].get("advisory_references", 0)
            lines.append(
                f"  • {source}: {advisory_references} advisories, "
                f"{checked_records} package record(s) checked"
            )
        else:
            details = []
            if current_count > 0:
                details.append(f"{current_count} affecting resolved version(s)")
            elif historical_count == 0 and unverified_count == 0:
                details.append("no vulnerabilities")
            else:
                details.append("0 affecting resolved version(s)")
            if historical_count > 0:
                details.append(f"{historical_count} historical/fixed entr{'y' if historical_count == 1 else 'ies'} in resolved dependency history")
            if unverified_count > 0:
                details.append(f"{unverified_count} unverified match(es)")
            lines.append(f"  • {source}: {', '.join(details)}")
    return lines


def _summarize_all_cve_sources(threat_intelligence):
    all_sources = {}
    multi_source_results = threat_intelligence.get("multi_source_cves") or {}
    for pkg_data in multi_source_results.values():
        for vuln in pkg_data.get("current", []):
            source = vuln.get("source", "unknown")
            all_sources.setdefault(source, {"current": 0, "historical": 0})
            all_sources[source]["current"] += 1
        for vuln in pkg_data.get("historical", []):
            source = vuln.get("source", "unknown")
            all_sources.setdefault(source, {"current": 0, "historical": 0})
            all_sources[source]["historical"] += 1

    github_hits = (threat_intelligence.get("github_advisories") or {}).get("hits", [])
    if github_hits:
        all_sources["github-advisories"] = {"current": len(github_hits), "historical": 0}

    cisa_unverified_hits = (threat_intelligence.get("cisa_kev") or {}).get("unverified_hits", [])
    if cisa_unverified_hits:
        all_sources.setdefault("cisa-kev", {"current": 0, "historical": 0})
        all_sources["cisa-kev"]["unverified"] = len(cisa_unverified_hits)

    deps_dev_hits = (threat_intelligence.get("deps_dev") or {}).get("hits", [])
    if deps_dev_hits:
        all_sources["deps-dev"] = {
            "current": len(deps_dev_hits),
            "historical": 0,
            "checked_records": len(deps_dev_hits),
            "advisory_references": sum(hit.get("advisory_count", 0) for hit in deps_dev_hits),
        }

    for source in ["osv", "cisa-kev", "github-advisories", "deps-dev"]:
        all_sources.setdefault(source, {"current": 0, "historical": 0, "unverified": 0})
    return all_sources


def _summarize_requested_package_sources(threat_intelligence, package_name):
    normalized_package = package_name.lower().replace("-", "_")
    source_data = {source: {"current": 0, "historical": 0, "unverified": 0} for source in ["osv", "cisa-kev", "github-advisories", "deps-dev"]}

    multi_source_results = threat_intelligence.get("multi_source_cves") or {}
    for key, pkg_data in multi_source_results.items():
        if key.lower().replace("-", "_") != normalized_package:
            continue
        for vuln in pkg_data.get("current", []):
            source = vuln.get("source", "unknown")
            source_data.setdefault(source, {"current": 0, "historical": 0})
            source_data[source]["current"] += 1
        for vuln in pkg_data.get("historical", []):
            source = vuln.get("source", "unknown")
            source_data.setdefault(source, {"current": 0, "historical": 0})
            source_data[source]["historical"] += 1
        for vuln in pkg_data.get("unverified", []):
            source = vuln.get("source", "unknown")
            source_data.setdefault(source, {"current": 0, "historical": 0, "unverified": 0})
            source_data[source]["unverified"] += 1

    github_hits = (threat_intelligence.get("github_advisories") or {}).get("hits", [])
    github_count = sum(1 for hit in github_hits if (hit.get("package") or "").lower().replace("-", "_") == normalized_package)
    if github_count:
        source_data["github-advisories"] = {"current": github_count, "historical": 0}

    deps_dev_hits = (threat_intelligence.get("deps_dev") or {}).get("hits", [])
    package_hits = [hit for hit in deps_dev_hits if (hit.get("package") or "").lower().replace("-", "_") == normalized_package]
    if package_hits:
        source_data["deps-dev"] = {
            "current": len(package_hits),
            "historical": 0,
            "checked_records": len(package_hits),
            "advisory_references": sum(hit.get("advisory_count", 0) for hit in package_hits),
        }

    return source_data


def _requested_package_historical_entries(resolution, threat_intelligence):
    entries = []
    multi_source_results = threat_intelligence.get("multi_source_cves") or {}
    requested_packages = _resolved_requested_packages(resolution)
    for package_name, version in requested_packages:
        pkg_historical = []
        for key, pkg_data in multi_source_results.items():
            if key.lower().replace("-", "_") != package_name.lower().replace("-", "_"):
                continue
            for vuln in pkg_data.get("historical", []):
                pkg_historical.append(
                    {
                        "package_name": package_name,
                        "package_version": version,
                        "cve_id": vuln.get("cve_id") or "unknown",
                        "affected_versions": vuln.get("affected_versions") or [],
                        "fixed_in_version": vuln.get("fixed_in_version"),
                    }
                )
        if pkg_historical:
            entries.append(((package_name, version), pkg_historical))
    return entries


def _format_summary(report, include_historical_details=False):
    lines = []
    environment = report.get("environment") or {}
    resolution = report.get("resolution", {})
    scan = report.get("scan") or {}
    provenance = report.get("provenance") or {}
    policy_result = report.get("policy") or {}
    risk = report.get("risk") or {}
    differential = report.get("differential") or {}
    sandbox = report.get("sandbox") or {}
    install = report.get("install") or {}
    evidence = sandbox.get("evidence") or {}
    static_analysis = sandbox.get("static_analysis") or {}
    cache = sandbox.get("cache") or {}
    trivy_results = sandbox.get("trivy_results") or {}
    verdicts = evidence.get("verdicts") or []

    packages = resolution.get("packages", [])
    requested_normalized = {
        package_name.lower().replace("-", "_")
        for package_name, _version in _resolved_requested_packages(resolution)
    }
    lines.append(f"Package: {report['package']}")
    lines.append(f"Mode: {report['mode']}")
    if environment:
        if environment.get("block"):
            lines.append(f"Runtime prerequisites: blocked ({environment.get('reason', 'unknown')})")
        else:
            lines.append("Runtime prerequisites: satisfied")
        python_env = environment.get("python") or {}
        pip_env = environment.get("pip") or {}
        if python_env.get("version"):
            lines.append(f"Python runtime: {python_env['version']} (need {python_env.get('required', python_env['version'])})")
        if pip_env.get("version"):
            lines.append(f"pip runtime: {pip_env['version']} (need {pip_env.get('required', pip_env['version'])})")
        elif pip_env.get("error"):
            lines.append(f"pip runtime: unavailable ({pip_env['error']})")
    if resolution.get("install_target"):
        lines.append(f"Install target: {resolution['install_target']}")
    if risk:
        lines.append(f"Risk: {risk.get('level', 'unknown')} ({risk.get('score', 0)}/100)")
        top_reason = (risk.get("reasons") or [{}])[0]
        if top_reason.get("message"):
            lines.append(f"Top risk reason: {top_reason['message']}")
    if packages:
        lines.append(f"Resolved packages: {len(packages)}")
    if scan:
        if scan.get("block"):
            lines.append(f"Scan verdict: blocked ({scan['reason']})")
        else:
            lines.append(_verdict_summary("Scan verdict", scan))
        blocked_package = scan.get("blocked_package")
        blocked_version = scan.get("blocked_version")
        blocked_source = scan.get("blocked_source")
        blocked_advisory_id = scan.get("blocked_advisory_id")
        if blocked_package:
            normalized_blocked = blocked_package.lower().replace("-", "_")
            blocked_label = "Blocked package" if normalized_blocked in requested_normalized else "Blocked dependency"
            detail_parts = []
            if blocked_source:
                detail_parts.append(f"source={blocked_source}")
            if blocked_advisory_id:
                detail_parts.append(str(blocked_advisory_id))
            detail_suffix = f" ({', '.join(detail_parts)})" if detail_parts else ""
            version_suffix = f"=={blocked_version}" if blocked_version else ""
            lines.append(f"{blocked_label}: {blocked_package}{version_suffix}{detail_suffix}")
        threat_intelligence = scan.get("threat_intelligence") or {}
        if threat_intelligence:
            feed_hits = len(threat_intelligence.get("hits", []))

            # Show custom threat feed results
            if feed_hits > 0:
                lines.append(f"Threat intelligence: {feed_hits} custom feed hit(s)")
            all_sources = _summarize_all_cve_sources(threat_intelligence)
            if all_sources:
                lines.append("CVE sources across all resolved packages:")
                lines.extend(_format_cve_source_lines(all_sources))

            requested_packages = _resolved_requested_packages(resolution)
            if len(requested_packages) > 1:
                lines.append("Requested package breakdown:")
                for package_name, version in requested_packages:
                    lines.append(f"  {package_name}=={version}:")
                    package_sources = _summarize_requested_package_sources(threat_intelligence, package_name)
                    lines.extend(f"    {line.strip()}" for line in _format_cve_source_lines(package_sources))

            if include_historical_details:
                historical_entries = _requested_package_historical_entries(resolution, threat_intelligence)
                if historical_entries:
                    lines.append("Historical/fixed CVEs:")
                    for (package_name, version), vulnerabilities in historical_entries:
                        lines.append(f"  {package_name}=={version}:")
                        for vuln in vulnerabilities[:5]:
                            affected_versions = ", ".join(vuln["affected_versions"]) if vuln["affected_versions"] else "unknown affected version range"
                            fixed_suffix = f"; fixed in {vuln['fixed_in_version']}" if vuln.get("fixed_in_version") else ""
                            lines.append(f"    - {vuln['cve_id']} ({affected_versions}{fixed_suffix})")
                        remainder = len(vulnerabilities) - 5
                        if remainder > 0:
                            lines.append(f"    - +{remainder} more")

            source_count = len(threat_intelligence.get("sources", []))
            if source_count:
                lines.append(f"Feed sources: {source_count} custom source(s)")
    if provenance:
        if provenance.get("block"):
            lines.append(f"Provenance verdict: blocked ({provenance['reason']})")
        else:
            lines.append(_verdict_summary("Provenance verdict", provenance))
        details = provenance.get("details") or []
        attested_files = sum((detail.get("signals") or {}).get("attested_file_count", 0) for detail in details)
        verified_files = sum((detail.get("signals") or {}).get("verified_attestation_file_count", 0) for detail in details)
        selected_files = sum((detail.get("signals") or {}).get("selected_file_count", 0) for detail in details)
        verification_available = any(
            (detail.get("signals") or {}).get("attestation_verification_available")
            for detail in details
        )
        if attested_files:
            verification_state = "available" if verification_available else "unavailable"
            suffix = ""
            unattested_files = max(selected_files - attested_files, 0)
            if unattested_files > 0:
                suffix = f"; {unattested_files} selected file(s) had no attestations"
            lines.append(
                "Attestation verification: "
                f"{verified_files}/{attested_files} attested file(s) verified, {verification_state}{suffix}"
            )
        failure_details = [
            (detail.get("signals") or {}).get("verification_failure")
            for detail in details
            if (detail.get("signals") or {}).get("verification_failure")
        ]
        if failure_details:
            first_failure = failure_details[0]
            lines.append(
                "First attestation failure: "
                f"{first_failure.get('filename', 'unknown file')} "
                f"({first_failure.get('error', 'unknown error')})"
            )
        unavailable_details = [
            (detail.get("signals") or {}).get("verification_unavailable")
            for detail in details
            if (detail.get("signals") or {}).get("verification_unavailable")
        ]
        if unavailable_details:
            first_unavailable = unavailable_details[0]
            lines.append(
                "Attestation infrastructure issue: "
                f"{first_unavailable.get('filename', 'unknown file')} "
                f"({first_unavailable.get('error', 'unknown error')})"
            )
    if differential:
        if differential.get("available"):
            lines.append(
                "Differential analysis: "
                f"baseline {differential.get('baseline_version')}, "
                f"{len(differential.get('findings', []))} finding(s), "
                f"{differential.get('added_files_count', 0)} added file(s)"
            )
            findings = differential.get("findings") or []
            if findings:
                lines.append(f"First differential finding: {findings[0]['code']}")
        else:
            lines.append(f"Differential analysis: unavailable ({differential.get('reason', 'unknown')})")
    if policy_result:
        if policy_result.get("block"):
            lines.append(f"Policy verdict: blocked ({policy_result['reason']})")
        else:
            lines.append(_verdict_summary("Policy verdict", policy_result))
        if policy_result.get("warnings"):
            lines.append(f"First policy warning: {policy_result['warnings'][0]}")
        elif policy_result.get("infos"):
            lines.append(f"First policy info: {policy_result['infos'][0]}")
    if sandbox:
        sandbox_state = "passed" if sandbox.get("success") else sandbox.get("error_type") or "failed"
        lines.append(f"Sandbox verdict: {sandbox_state}")
        backend = (sandbox.get("isolation") or {}).get("backend")
        if backend:
            lines.append(f"Sandbox backend: {backend}")
        trust = sandbox.get("trust") or {}
        if trust.get("level"):
            lines.append(f"Sandbox trust: {trust['level']}")
            if trust.get("warnings"):
                lines.append(f"First sandbox warning: {trust['warnings'][0]}")
            elif trust.get("infos"):
                lines.append(f"First sandbox info: {trust['infos'][0]}")
        if cache:
            cache_state = "hit" if cache.get("hit") else "miss"
            lines.append(f"Bundle cache: {cache_state}")
        if trivy_results:
            vulnerabilities = trivy_results.get("vulnerabilities") or []
            if trivy_results.get("scanned"):
                trivy_state = "blocked" if trivy_results.get("should_block") else "passed"
                lines.append(f"Trivy verdict: {trivy_state} ({len(vulnerabilities)} finding(s))")
            else:
                lines.append("Trivy verdict: unavailable")
            if vulnerabilities:
                first_vuln = vulnerabilities[0]
                severity = first_vuln.get("severity", "UNKNOWN")
                vuln_id = first_vuln.get("id", "unknown")
                lines.append(f"First Trivy finding: {severity} {vuln_id}")
            if trivy_results.get("warnings"):
                lines.append(f"First Trivy warning: {trivy_results['warnings'][0]}")
        bundle = sandbox.get("bundle") or {}
        if bundle:
            lines.append(
                "Locked bundle: "
                f"{len(bundle.get('downloaded_files', []))} artifact(s), "
                f"{len(bundle.get('artifact_hashes', {}))} hash(es)"
            )
        if static_analysis:
            lines.append(
                "Static analysis: "
                f"{static_analysis.get('finding_count', 0)} finding(s), "
                f"{static_analysis.get('high_count', 0)} high, "
                f"{static_analysis.get('medium_count', 0)} medium"
            )
            if static_analysis.get("blocked"):
                first_static = static_analysis.get("findings", [{}])[0]
                lines.append(
                    f"First static finding: {first_static.get('code', 'unknown')} "
                    f"({first_static.get('file', 'unknown file')})"
                )
        if evidence:
            lines.append(
                "Sandbox evidence: "
                f"{evidence.get('write_count', 0)} writes, "
                f"{len(evidence.get('allowed_subprocesses', []))} allowed subprocess probe(s), "
                f"{len(evidence.get('blocked_events', []))} blocked event(s)"
            )
            syscall_counts = evidence.get("syscall_counts") or {}
            if syscall_counts:
                lines.append(
                    "Syscall trace: "
                    f"{syscall_counts.get('filesystem_mutation', 0)} filesystem, "
                    f"{syscall_counts.get('process_exec', 0)} process, "
                    f"{syscall_counts.get('network', 0)} network"
                )
            lines.append(
                "Import checks: "
                f"{len(evidence.get('imported_modules', []))} imported, "
                f"{len(evidence.get('skipped_imports', []))} skipped, "
                f"{len(evidence.get('import_failures', []))} failed"
            )
            if verdicts:
                high_count = sum(1 for verdict in verdicts if verdict["severity"] == "high")
                info_count = sum(1 for verdict in verdicts if verdict["severity"] == "info")
                medium_count = sum(1 for verdict in verdicts if verdict["severity"] == "medium")
                lines.append(
                    "Behavioral verdicts: "
                    f"{high_count} high, {medium_count} medium, {info_count} info"
                )
            if evidence.get("import_failures"):
                first_failure = evidence["import_failures"][0]
                error_type = first_failure.get("type", "ImportError")
                error_message = first_failure.get("message")
                error_suffix = f": {error_message}" if error_message else ""
                lines.append(
                    f"First import failure: {first_failure['module']} ({error_type}{error_suffix})"
                )
            if evidence.get("blocked_events"):
                first = evidence["blocked_events"][0]
                lines.append(f"First blocked event: {first['category']}")
    if install:
        if install.get("success"):
            source = install.get("source")
            project_url = _pypi_project_url_for_target(install.get("target"))
            project_suffix = f", {project_url}" if project_url else ""
            source_suffix = f", source={source}" if source else ""
            lines.append(f"Host install: succeeded ({install.get('target')}{project_suffix}{source_suffix})")
            project_links = _pypi_project_links(report)
            if len(project_links) > 1:
                preview = project_links[:5]
                remainder = len(project_links) - len(preview)
                lines.append("PyPI project links:")
                lines.extend(f"  - {item}" for item in preview)
                if remainder > 0:
                    lines.append(f"  - +{remainder} more")
        elif install.get("blocked"):
            lines.append(f"Host install: blocked ({install.get('reason', 'policy')})")
        elif install.get("skipped"):
            lines.append(f"Host install: skipped ({install.get('reason', 'unavailable')})")
        else:
            lines.append("Host install: failed")
    receipt = report.get("receipt") or {}
    if receipt.get("receipt_id"):
        lines.append(f"Receipts: {receipt['decision']} ({_receipt_count_label(1)})")
        lines.append(f"Receipt ID: {receipt['receipt_id']}")
        paths = receipt.get("paths") or ([receipt["path"]] if receipt.get("path") else [])
        if paths:
            lines.append("Receipt path:")
            lines.extend(f"  - {path}" for path in paths)
    elif receipt.get("receipts"):
        lines.append(
            f"Receipts: {receipt.get('decision', 'unknown')} "
            f"({_receipt_count_label(len(receipt['receipts']))})"
        )
        lines.append("Receipt path:")
        for entry in receipt["receipts"]:
            label = entry.get("package") or "package"
            version = entry.get("package_version")
            package_label = f"{label}=={version}" if version else label
            lines.append(f"  - {package_label}: {entry['path']}")
    elif receipt.get("error"):
        lines.append(f"Receipt: unavailable ({receipt['error']})")
    return "\n".join(lines)


def _render_report(report, output_mode="both"):
    prepared = _prepare_report_with_receipt(report)
    sections = []
    include_historical_details = bool(report.get("_show_historical_details"))
    if output_mode in {"summary", "both"}:
        sections.append("Summary\n" + _format_summary(prepared, include_historical_details=include_historical_details))
    if output_mode in {"json", "both"}:
        sections.append("Report\n" + json.dumps(prepared, indent=2, sort_keys=True))
    return "\n\n".join(sections)


def _echo_summary(report):
    prepared = _prepare_report_with_receipt(report)
    include_historical_details = bool(report.get("_show_historical_details"))
    click.echo("Summary")
    for line in _format_summary(prepared, include_historical_details=include_historical_details).splitlines():
        color = _summary_line_color(line)
        if color:
            click.secho(line, fg=color)
        else:
            click.echo(line)


def _determine_exit_code(report):
    install = report.get("install") or {}
    if install.get("success"):
        return EXIT_OK
    if install.get("skipped") and install.get("reason") == "sandbox_unavailable":
        return EXIT_SANDBOX_UNAVAILABLE
    if install.get("blocked"):
        return EXIT_BLOCKED
    if install.get("attempted"):
        return EXIT_INSTALL_FAILED
    return EXIT_OK


def _finish(report, output_mode):
    prepared = _prepare_report_with_receipt(report)
    if output_mode == "summary":
        click.echo("")
        _echo_summary(prepared)
    elif output_mode == "json":
        # Pure JSON on stdout, no human text mixed in -- this is the stable, documented
        # contract any language can parse (final-plan.md Phase 0).
        click.echo(json.dumps(prepared, indent=2, sort_keys=True))
    else:
        click.echo("")
        _echo_summary(prepared)
        click.echo("")
        click.echo("Report\n" + json.dumps(prepared, indent=2, sort_keys=True))
    raise SystemExit(_determine_exit_code(report))
