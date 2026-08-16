from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from contextlib import contextmanager
from importlib import metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote
import click
from packaging.version import InvalidVersion, Version
import requests

from .ecosystems import PYPI_ECOSYSTEM, ecosystem_for_name, package_records, resolve_node_tool
from .input_sources import load_input_source
from .receipts import ReceiptUnavailableError, delete_receipts, list_receipts, verify_receipt, write_receipt
from .runtime import pip_command, self_invoke_command
from .routing import (
    dismiss_routing_prompt,
    disable_routing as disable_routing_shim,
    enable_routing as enable_routing_shim,
    get_routing_status,
    should_prompt_for_routing,
)
from .sandbox import run_sandbox
from .scanner import scan_vulnerabilities
from .ui import serve_ui

EXIT_OK = 0
EXIT_BLOCKED = 10
EXIT_SANDBOX_UNAVAILABLE = 11
EXIT_INSTALL_FAILED = 12
REPORT_SCHEMA_VERSION = "1"
MIN_SECURE_PYTHON = (3, 11, 4)
MIN_SECURE_PYTHON_LABEL = "3.11.4"
MIN_SECURE_PIP_VERSION = Version("25.3")
MIN_SECURE_PIP_LABEL = "25.3"


@click.group()
def cli():
    pass


# When True, progress/stage messages go to stderr instead of stdout, so stdout stays pure
# JSON for `--output json` (final-plan.md Phase 0's "no human text mixed in" rule). Set once
# per command invocation by install/scan before any stage output happens.
_JSON_ONLY_OUTPUT = False


def _progress_stream():
    return sys.stderr if _JSON_ONLY_OUTPUT else sys.stdout


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


def _runtime_environment_report():
    python_version = ".".join(str(part) for part in sys.version_info[:3])
    python_ok = sys.version_info >= MIN_SECURE_PYTHON
    python_requirement = f"Python>={MIN_SECURE_PYTHON_LABEL}"

    pip_version = None
    pip_ok = False
    pip_error = None
    try:
        pip_version = metadata.version("pip")
        pip_ok = Version(pip_version) >= MIN_SECURE_PIP_VERSION
    except metadata.PackageNotFoundError:
        pip_error = "pip is not installed in this interpreter environment"
    except InvalidVersion:
        pip_error = f"pip has an unrecognized version string: {pip_version!r}"

    issues = []
    if not python_ok:
        issues.append(f"requires {python_requirement} (running {python_version})")
    if pip_error:
        issues.append(pip_error)
    elif not pip_ok:
        issues.append(
            f"requires pip>={MIN_SECURE_PIP_LABEL} because depshieldx shells out to the local pip (running {pip_version})"
        )

    return {
        "block": bool(issues),
        "reason": "; ".join(issues) if issues else None,
        "python": {
            "version": python_version,
            "required": python_requirement,
            "ok": python_ok,
        },
        "pip": {
            "version": pip_version,
            "required": f"pip>={MIN_SECURE_PIP_LABEL}",
            "ok": pip_ok,
            "error": pip_error,
        },
    }


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


def _prepare_report(report):
    return {key: value for key, value in dict(report).items() if not key.startswith("_")}


def _prepare_report_with_receipt(report):
    prepared = _prepare_report(report)
    if "receipt" not in prepared or not prepared["receipt"]:
        try:
            prepared["receipt"] = write_receipt(prepared)
        except ReceiptUnavailableError as exc:
            prepared["receipt"] = {
                "decision": "unavailable",
                "error": str(exc),
            }
    return prepared


def _run_cli_command(command, verbose=False):
    return subprocess.run(
        command,
        check=True,
        capture_output=not verbose,
        text=not verbose,
    )


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


def _show_routing_enabled_message(status):
    _echo_success("pip routing enabled.")
    click.echo(f"   Add this to your shell to activate it: {status['activation_hint']}")


def _show_routing_status(status):
    click.echo(f"Routing status: {'enabled' if status['enabled'] else 'disabled'}")
    click.echo("Manage later with: depshieldx routing enable | depshieldx routing disable")
    if status["enabled"]:
        click.echo(f"Activation: {status['activation_hint']}")


def _normalize_package_name(package_name):
    return package_name.strip().lower().replace("_", "-") if package_name else ""


def _handle_routing_choice(enable_flag=False, disable_flag=False, package_name=None):
    if disable_flag:
        status = disable_routing_shim()
        click.echo("pip routing disabled.")
        return status

    if enable_flag:
        status = enable_routing_shim()
        _show_routing_enabled_message(status)
        return status

    if sys.stdin.isatty() and sys.stdout.isatty() and should_prompt_for_routing():
        normalized_name = _normalize_package_name(package_name)
        if normalized_name == "depshieldx":
            click.echo("Optional pip routing can send simple 'pip install <package>' commands through depshieldx.")
            click.echo("Enable later with: depshieldx routing enable")
            click.echo("Disable later with: depshieldx routing disable")
            prompt = "Enable optional pip routing now?"
        else:
            prompt = "Route future simple 'pip install <package>' commands through depshieldx?"

        if click.confirm(prompt, default=False):
            status = enable_routing_shim()
            _show_routing_enabled_message(status)
            return status
        status = dismiss_routing_prompt()
        click.echo("Routing prompt dismissed. Manage later with: depshieldx routing enable")
        return status
    return get_routing_status()


def _prepare_routing_for_install(package_name, enable_flag=False, disable_flag=False):
    if _normalize_package_name(package_name) != "depshieldx":
        return None
    return _handle_routing_choice(enable_flag, disable_flag, package_name)


def _finalize_routing_after_install(package_name, enable_flag=False, disable_flag=False, routing_status=None):
    if _normalize_package_name(package_name) == "depshieldx":
        status = routing_status or get_routing_status()
        _show_routing_status(status)
        return status
    return _handle_routing_choice(enable_flag, disable_flag, package_name)


def _extract_simple_install_target(pip_args):
    if not pip_args or pip_args[0] != "install":
        return None

    unsupported_flags = {"-r", "--requirement", "-e", "--editable", "-c", "--constraint"}
    requirements = []
    for arg in pip_args[1:]:
        if arg in unsupported_flags:
            return None
        if arg.startswith("-"):
            continue
        requirements.append(arg)

    if len(requirements) != 1:
        return None
    return requirements[0]


def _load_cli_input(targets, requirement_file=None, lockfile=None, pyproject_file=None):
    try:
        return load_input_source(
            targets,
            requirement_file=requirement_file,
            lockfile=lockfile,
            pyproject_file=pyproject_file,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc


def _ecosystem_for_input_source(input_source):
    return ecosystem_for_name(input_source.ecosystem)


def _resolve_input_source(input_source, ecosystem):
    return ecosystem.resolve(
        input_source.pip_args,
        input_source.requested_targets,
        input_source.label,
        source_type=input_source.source_type,
    )


def _record_resolution(report, resolution):
    report["resolution"] = {
        "packages": resolution.packages,
        "install_target": resolution.install_target,
        "resolved_versions": resolution.resolved_versions,
        "selected_artifacts": resolution.selected_artifacts,
        "requested_targets": resolution.requested_targets,
        "source_type": resolution.source_type,
        "resolution_succeeded": resolution.resolution_succeeded,
        "resolution_error": resolution.resolution_error,
        "package_records": [record.__dict__ for record in package_records(report["ecosystem"], resolution)],
    }


def _uninstall_args_for_input_source(input_source):
    if input_source.source_type == "requirements":
        return input_source.pip_args[:]

    package_names = []
    seen = set()
    for target in input_source.requested_targets:
        package_name = _package_name_from_requirement(target) or target.strip()
        if not package_name:
            continue
        normalized = package_name.lower().replace("-", "_")
        if normalized in seen:
            continue
        seen.add(normalized)
        package_names.append(package_name)
    return package_names


def _handle_resolution_failure(report, resolution, output_mode):
    message = resolution.resolution_error or "pip could not resolve the requested install target"
    _echo_error(f"Resolution failed: {message}")
    report["install"] = {
        "attempted": False,
        "success": False,
        "blocked": True,
        "reason": "resolution",
    }
    _finish(report, output_mode)


def _run_fast_checks(resolution, ecosystem=PYPI_ECOSYSTEM, verbose=False):
    def _provenance_failure(exc):
        message = str(exc).strip() or exc.__class__.__name__
        return {
            "block": True,
            "reason": f"provenance check failed unexpectedly: {message}",
            "warnings": [],
            "infos": [],
            "details": [],
        }

    def _scan_failure(exc):
        message = str(exc).strip() or exc.__class__.__name__
        return {
            "block": True,
            "reason": f"vulnerability scan failed unexpectedly: {message}",
            "warnings": [],
            "infos": [],
            "threat_intelligence": {
                "hits": [],
                "sources": [],
                "osv": {"hits": [], "warnings": [], "source": "osv"},
                "github_advisories": {"hits": [], "warnings": [], "source": "github_advisories"},
                "cisa_kev": {"hits": [], "warnings": [], "source": "cisa-kev"},
                "deps_dev": {"hits": [], "warnings": [], "source": "deps_dev"},
                "multi_source_cves": {},
                "trivy": None,
            },
        }

    def _run_guarded(func, failure_factory, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except BaseException as exc:
            return failure_factory(exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        provenance_future = executor.submit(
            _run_guarded,
            ecosystem.check_provenance,
            _provenance_failure,
            resolution.resolved_versions,
            selected_artifacts=resolution.selected_artifacts,
            verbose=verbose,
        )
        scan_future = executor.submit(
            _run_guarded,
            scan_vulnerabilities,
            _scan_failure,
            resolution.packages,
            resolved_versions=resolution.resolved_versions,
            ecosystem=ecosystem.name,
        )
        return provenance_future.result(), scan_future.result()


def _build_report(package_name, mode, operation, ecosystem=PYPI_ECOSYSTEM):
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "ecosystem": ecosystem.name,
        "package": package_name,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "operation": operation,
        "environment": {},
        "resolution": {},
        "provenance": None,
        "scan": None,
        "sandbox": None,
        "install": None,
    }


def _handle_unexpected_command_error(report, output_mode, exc):
    _echo_error(f"Unexpected failure: {exc}")
    report["install"] = {
        "attempted": False,
        "success": False,
        "blocked": True,
        "reason": "internal_error",
        "error": str(exc),
    }
    _finish(report, output_mode)


def _enforce_runtime_prerequisites(report, output_mode):
    environment = _runtime_environment_report()
    report["environment"] = environment
    if not environment.get("block"):
        return
    _echo_error(f"Runtime prerequisite failed: {environment['reason']}")
    report["install"] = {
        "attempted": False,
        "success": False,
        "blocked": True,
        "reason": "environment",
    }
    _finish(report, output_mode)


def _sandbox_report(sandbox_result):
    return {
        "success": sandbox_result.success,
        "downloaded_files": sandbox_result.downloaded_files,
        "error": sandbox_result.error,
        "error_type": sandbox_result.error_type,
        "isolation": sandbox_result.isolation,
        "cache": sandbox_result.cache,
        "trivy_results": sandbox_result.trivy_results,
    }


def _perform_host_install(
    report,
    resolution,
    package_name,
    verbose,
    enable_routing,
    disable_routing,
    output_mode,
    source=None,
    ecosystem=PYPI_ECOSYSTEM,
):
    routing_status = _prepare_routing_for_install(package_name, enable_routing, disable_routing)
    try:
        with _stage_loader("Installing resolved package set on host...", verbose=verbose):
            with ecosystem.host_install_command(resolution) as install_command:
                _run_cli_command(install_command, verbose=verbose)
        report["install"] = {
            "attempted": True,
            "success": True,
            "target": resolution.install_target,
        }
        if source:
            report["install"]["source"] = source
        _finalize_routing_after_install(package_name, enable_routing, disable_routing, routing_status)
    except (subprocess.CalledProcessError, requests.RequestException, RuntimeError, OSError) as exc:
        report["install"] = {
            "attempted": True,
            "success": False,
            "target": resolution.install_target,
            "error": str(exc),
        }
        if source:
            report["install"]["source"] = source
        _finish(report, output_mode)
        raise


def _run_fast_flow(
    report,
    resolution,
    package_name,
    output_mode,
    do_install,
    verbose=False,
    enable_routing=False,
    disable_routing=False,
    ecosystem=PYPI_ECOSYSTEM,
):
    with _stage_loader(
        "Checking provenance and vulnerability sources for the resolved package set...",
        verbose=verbose,
        animated=False,
    ):
        provenance_result, scan_result = _run_fast_checks(resolution, ecosystem=ecosystem, verbose=verbose)
    report["provenance"] = provenance_result
    report["scan"] = scan_result

    if provenance_result["block"]:
        _echo_error(f"BLOCKED: {provenance_result['reason']}")
        report["install"] = {
            "attempted": False,
            "success": False,
            "blocked": True,
            "reason": "provenance",
        }
        _finish(report, output_mode)
    if scan_result["block"]:
        _echo_error(f"BLOCKED: {scan_result['reason']}")
        report["install"] = {
            "attempted": False,
            "success": False,
            "blocked": True,
            "reason": "scan",
        }
        _finish(report, output_mode)

    _emit_result_messages("Provenance", provenance_result)
    _emit_result_messages("Scan", scan_result)

    if not do_install:
        _echo_success("Fast scan completed. No install performed.")
        report["install"] = {"attempted": False, "success": False, "skipped": True, "reason": "scan_only"}
        _finish(report, output_mode)

    _echo_success("Fast scan passed. Installing normally...")
    _perform_host_install(
        report,
        resolution,
        package_name,
        verbose,
        enable_routing,
        disable_routing,
        output_mode,
        ecosystem=ecosystem,
    )
    _finish(report, output_mode)


def _run_deep_flow(
    report,
    input_source,
    resolution,
    package_name,
    output_mode,
    do_install,
    no_cache=False,
    verbose=False,
    enable_routing=False,
    disable_routing=False,
):
    with _stage_loader(
        "Checking provenance and vulnerability sources for the resolved package set...",
        verbose=verbose,
        animated=False,
    ):
        provenance_result, scan_result = _run_fast_checks(resolution, verbose=verbose)
    report["provenance"] = provenance_result
    report["scan"] = scan_result
    if provenance_result["block"]:
        _echo_error(f"BLOCKED: {provenance_result['reason']}")
        report["install"] = {
            "attempted": False,
            "success": False,
            "blocked": True,
            "reason": "provenance",
        }
        _finish(report, output_mode)
    if scan_result["block"]:
        _echo_error(f"BLOCKED: {scan_result['reason']}")
        report["install"] = {
            "attempted": False,
            "success": False,
            "blocked": True,
            "reason": "scan",
        }
        _finish(report, output_mode)

    _emit_result_messages("Provenance", provenance_result)
    _emit_result_messages("Scan", scan_result)
    with _stage_loader("Running Docker sandbox install and Trivy scan...", verbose=verbose):
        sandbox_result = run_sandbox(
            input_source.requested_targets,
            resolved_versions=resolution.resolved_versions,
            keep_bundle=False,
            cache_enabled=not no_cache,
            verbose=verbose,
            require_docker=True,
            block_on_static_analysis=False,
            block_on_trivy=True,
        )
    report["sandbox"] = _sandbox_report(sandbox_result)

    if not sandbox_result.success:
        if sandbox_result.error_type == "environment":
            _echo_error(f"Sandbox unavailable: {sandbox_result.error}")
            report["install"] = {
                "attempted": False,
                "success": False,
                "blocked": False,
                "skipped": True,
                "reason": "sandbox_unavailable",
            }
        elif sandbox_result.error_type == "trivy":
            _echo_error(f"Installation blocked by Trivy: {sandbox_result.error}")
            report["install"] = {
                "attempted": False,
                "success": False,
                "blocked": True,
                "reason": "trivy",
            }
        else:
            _echo_error("Installation blocked by sandbox.")
            report["install"] = {
                "attempted": False,
                "success": False,
                "blocked": True,
                "reason": "sandbox_failed",
            }
        _finish(report, output_mode)

    if not do_install:
        _echo_success("Docker sandbox and Trivy scan passed. No install performed.")
        report["install"] = {"attempted": False, "success": False, "skipped": True, "reason": "scan_only"}
        _finish(report, output_mode)

    _echo_success("Docker sandbox and Trivy scan passed. Installing normally...")
    _perform_host_install(
        report,
        resolution,
        package_name,
        verbose,
        enable_routing,
        disable_routing,
        output_mode,
        source="host_pip",
    )
    _finish(report, output_mode)

@cli.command()
@click.argument("targets", nargs=-1)
@click.option("-r", "--requirement", "requirement_file", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Install from a requirements file")
@click.option("--lockfile", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Install from a lockfile such as uv.lock")
@click.option("--pyproject", "pyproject_file", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Install dependencies from a pyproject.toml file")
@click.option("--fast", is_flag=True, help="Resolve, check provenance, and query the 4 vulnerability sources before install")
@click.option("--deep", is_flag=True, help="Full behavioral sandbox scan")
@click.option("--no-cache", is_flag=True, help="Disable local deep-scan bundle cache")
@click.option("--verbose", is_flag=True, help="Show underlying pip and sandbox command output")
@click.option("--enable-routing", is_flag=True, help="Enable the optional pip-to-depshieldx routing shim after install")
@click.option("--disable-routing", is_flag=True, help="Disable the optional pip-to-depshieldx routing shim for future installs")
@click.option(
    "--full-report",
    is_flag=True,
    help="Show the full JSON report after the human summary",
)
@click.option(
    "--output",
    "output_mode",
    type=click.Choice(["summary", "json", "both"], case_sensitive=False),
    default="summary",
    show_default=True,
    help="Choose report output format for humans or automation",
)
def install(
    targets,
    requirement_file,
    lockfile,
    pyproject_file,
    fast,
    deep,
    no_cache,
    verbose,
    enable_routing,
    disable_routing,
    full_report,
    output_mode,
):
    """Install a Python package safely."""
    if enable_routing and disable_routing:
        raise click.UsageError("Use only one of --enable-routing or --disable-routing")
    if fast and deep:
        raise click.UsageError("Use only one of --fast or --deep")

    if full_report and output_mode == "summary":
        output_mode = "both"

    global _JSON_ONLY_OUTPUT
    _JSON_ONLY_OUTPUT = output_mode == "json"

    routing_status = None
    mode = "deep" if deep else "fast"
    input_source = _load_cli_input(
        targets,
        requirement_file=requirement_file,
        lockfile=lockfile,
        pyproject_file=pyproject_file,
    )
    package_name = input_source.label
    ecosystem = _ecosystem_for_input_source(input_source)
    if deep and ecosystem is not PYPI_ECOSYSTEM:
        raise click.UsageError(
            f"--deep is not supported yet for the {ecosystem.name} ecosystem (fast mode only in this phase)"
        )

    report = _build_report(package_name, mode, "install", ecosystem=ecosystem)
    report["_show_historical_details"] = verbose or output_mode == "both"

    try:
        _enforce_runtime_prerequisites(report, output_mode)
        with _stage_loader(f"Resolving dependencies for {package_name}...", verbose=verbose):
            resolution = _resolve_input_source(input_source, ecosystem)
        _record_resolution(report, resolution)
        if not resolution.resolution_succeeded:
            _handle_resolution_failure(report, resolution, output_mode)
        _echo_step(f"Found {len(resolution.packages)} package(s)")

        if deep:
            _run_deep_flow(
                report,
                input_source,
                resolution,
                package_name,
                output_mode,
                do_install=True,
                no_cache=no_cache,
                verbose=verbose,
                enable_routing=enable_routing,
                disable_routing=disable_routing,
            )
            return
        _run_fast_flow(
            report,
            resolution,
            package_name,
            output_mode,
            do_install=True,
            verbose=verbose,
            enable_routing=enable_routing,
            disable_routing=disable_routing,
            ecosystem=ecosystem,
        )
    except SystemExit:
        raise
    except BaseException as exc:
        _handle_unexpected_command_error(report, output_mode, exc)


@cli.command()
@click.argument("targets", nargs=-1)
@click.option("-r", "--requirement", "requirement_file", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Scan packages from a requirements file")
@click.option("--lockfile", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Scan packages from a lockfile such as uv.lock")
@click.option("--pyproject", "pyproject_file", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Scan dependencies from a pyproject.toml file")
@click.option("--fast", is_flag=True, help="Resolve, check provenance, and query the 4 vulnerability sources only")
@click.option("--deep", is_flag=True, help="Resolve, check provenance, and run Docker + Trivy without host install")
@click.option("--no-cache", is_flag=True, help="Disable local deep-scan bundle cache")
@click.option("--verbose", is_flag=True, help="Show underlying resolver command output when relevant")
@click.option(
    "--full-report",
    is_flag=True,
    help="Show the full JSON report after the human summary",
)
@click.option(
    "--output",
    "output_mode",
    type=click.Choice(["summary", "json", "both"], case_sensitive=False),
    default="summary",
    show_default=True,
    help="Choose report output format for humans or automation",
)
def scan(targets, requirement_file, lockfile, pyproject_file, fast, deep, no_cache, verbose, full_report, output_mode):
    """Scan one or more packages without installing them."""
    if fast and deep:
        raise click.UsageError("Use only one of --fast or --deep")
    if full_report and output_mode == "summary":
        output_mode = "both"

    global _JSON_ONLY_OUTPUT
    _JSON_ONLY_OUTPUT = output_mode == "json"

    mode = "deep" if deep else "fast"
    input_source = _load_cli_input(
        targets,
        requirement_file=requirement_file,
        lockfile=lockfile,
        pyproject_file=pyproject_file,
    )
    package_name = input_source.label
    ecosystem = _ecosystem_for_input_source(input_source)
    if deep and ecosystem is not PYPI_ECOSYSTEM:
        raise click.UsageError(
            f"--deep is not supported yet for the {ecosystem.name} ecosystem (fast mode only in this phase)"
        )

    report = _build_report(package_name, mode, "scan", ecosystem=ecosystem)
    report["_show_historical_details"] = verbose or output_mode == "both"

    try:
        _enforce_runtime_prerequisites(report, output_mode)
        with _stage_loader(f"Resolving dependencies for {package_name}...", verbose=verbose):
            resolution = _resolve_input_source(input_source, ecosystem)
        _record_resolution(report, resolution)
        if not resolution.resolution_succeeded:
            _handle_resolution_failure(report, resolution, output_mode)
        _echo_step(f"Found {len(resolution.packages)} package(s)")
        if deep:
            _run_deep_flow(
                report,
                input_source,
                resolution,
                package_name,
                output_mode,
                do_install=False,
                no_cache=no_cache,
                verbose=verbose,
            )
            return
        _run_fast_flow(
            report,
            resolution,
            package_name,
            output_mode,
            do_install=False,
            verbose=verbose,
            ecosystem=ecosystem,
        )
    except SystemExit:
        raise
    except BaseException as exc:
        _handle_unexpected_command_error(report, output_mode, exc)


@cli.command()
@click.argument("targets", nargs=-1)
@click.option("-r", "--requirement", "requirement_file", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Uninstall packages from a requirements file")
@click.option("--lockfile", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Uninstall packages listed in a lockfile such as uv.lock")
@click.option("--pyproject", "pyproject_file", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Uninstall dependencies listed in a pyproject.toml file")
@click.option("--verbose", is_flag=True, help="Show underlying pip uninstall command output")
def uninstall(targets, requirement_file, lockfile, pyproject_file, verbose):
    """Uninstall one or more Python packages."""
    input_source = _load_cli_input(
        targets,
        requirement_file=requirement_file,
        lockfile=lockfile,
        pyproject_file=pyproject_file,
    )
    ecosystem = _ecosystem_for_input_source(input_source)
    if ecosystem is not PYPI_ECOSYSTEM:
        raise click.UsageError(
            f"uninstall is not supported yet for the {ecosystem.name} ecosystem "
            f"(npm's lockfile-implied uninstall semantics need their own design pass)"
        )
    uninstall_args = _uninstall_args_for_input_source(input_source)
    if not uninstall_args:
        raise click.UsageError("Could not determine which packages to uninstall")

    with _stage_loader(f"Uninstalling packages for {input_source.label}...", verbose=verbose):
        _run_cli_command(ecosystem.uninstall_command(uninstall_args), verbose=verbose)
    _echo_success("Uninstall completed.")
    if requirement_file:
        click.echo(f"Removed packages listed in {input_source.label}.")
    else:
        click.echo("Removed packages: " + ", ".join(uninstall_args))


@cli.group()
def routing():
    """Manage the optional pip-to-depshieldx routing shim."""


@routing.command("status")
def routing_status():
    status = get_routing_status()
    click.echo(f"Routing: {'enabled' if status['enabled'] else 'disabled'}")
    click.echo(f"Shim path: {status['shim_path']}")
    click.echo(f"Activation: {status['activation_hint']}")


@routing.command("enable")
def routing_enable():
    status = enable_routing_shim()
    _show_routing_enabled_message(status)


@routing.command("disable")
def routing_disable():
    disable_routing_shim()
    click.echo("pip routing disabled.")


@cli.group()
def receipts():
    """Inspect signed local install receipts."""


@receipts.command("list")
@click.option("--limit", type=int, default=20, show_default=True, help="Maximum number of receipts to show")
def receipts_list(limit):
    rows = list_receipts(limit=max(limit, 1))
    if not rows:
        click.echo("No receipts found.")
        return
    for row in rows:
        click.echo(
            f"{row.get('created_at', 'unknown')}  {row.get('decision', 'unknown')}  "
            f"{row.get('package', 'unknown')}  {row.get('receipt_id', 'unknown')}"
        )
        click.echo(f"  {row.get('path', '')}")


@receipts.command("verify")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str))
def receipts_verify(path):
    result = verify_receipt(path)
    if result["valid"]:
        click.secho(f"Receipt valid: {result['path']}", fg="green")
        raise SystemExit(EXIT_OK)
    click.secho(f"Receipt invalid: {result['path']}", fg="red")
    raise SystemExit(EXIT_BLOCKED)


@receipts.command("delete")
def receipts_delete():
    deleted = delete_receipts()
    click.echo(f"Deleted {deleted} receipt(s).")


@cli.command()
@click.option(
    "--port",
    type=click.IntRange(0, 65535),
    default=0,
    show_default=True,
    help="Local TCP port for the browser UI. Use 0 to auto-select a free port.",
)
@click.option(
    "--open/--no-open",
    "open_browser",
    default=True,
    show_default=True,
    help="Open the UI in your default browser after the local server starts.",
)
def ui(port, open_browser):
    """Open a local browser UI for receipts and cache entries."""
    try:
        serve_ui(port=port, open_browser=open_browser, echo=click.echo)
    except OSError as exc:
        raise click.ClickException(f"Could not start the local UI server: {exc}") from exc


@cli.command("route-pip", hidden=True, context_settings={"ignore_unknown_options": True})
@click.argument("pip_args", nargs=-1, type=click.UNPROCESSED)
def route_pip(pip_args):
    """Internal helper used by the optional pip shim."""
    args = list(pip_args)
    package_target = _extract_simple_install_target(args)
    if package_target:
        click.echo("Routing pip install through depshieldx...")
        command = self_invoke_command(["install", package_target])
        if os.environ.get("DEPSHIELDX_ROUTE_DEEP") == "1":
            command.append("--deep")
        result = subprocess.run(command, check=False)
        raise SystemExit(result.returncode)

    click.secho(
        "depshieldx routing only intercepts simple 'pip install <package>' commands. Passing through to pip.",
        fg="yellow",
        err=True,
    )
    result = subprocess.run(pip_command(args), check=False)
    raise SystemExit(result.returncode)


# manager -> its lockfile name, used to auto-detect what to scan when the shim
# intercepts a plain "install everything from the lockfile in cwd" command.
NPM_FAMILY_LOCKFILES = {
    "npm": "package-lock.json",
    "yarn": "yarn.lock",
    "pnpm": "pnpm-lock.yaml",
}


def _is_plain_npm_family_install(args):
    # Only intercept a bare "install"/"i"/"ci" with no specific package named --
    # NpmEcosystem's resolve() only supports lockfile-based resolution in this
    # phase, not resolving an ad-hoc new package the way "npm install left-pad"
    # would need. Anything else passes through untouched, same principle as the
    # pip shim only intercepting "pip install <single-package>".
    if not args or args[0] not in ("install", "i", "ci"):
        return False
    return all(arg.startswith("-") for arg in args[1:])


def _route_npm_family(manager, args):
    lockfile_name = NPM_FAMILY_LOCKFILES[manager]
    lockfile_path = Path.cwd() / lockfile_name
    if _is_plain_npm_family_install(args) and lockfile_path.exists():
        click.echo(f"Routing {manager} install through depshieldx...")
        command = self_invoke_command(["install", "--lockfile", str(lockfile_path)])
        result = subprocess.run(command, check=False)
        raise SystemExit(result.returncode)

    click.secho(
        f"depshieldx routing only intercepts a plain '{manager} install' when {lockfile_name} is present. "
        f"Passing through to {manager}.",
        fg="yellow",
        err=True,
    )
    result = subprocess.run([resolve_node_tool(manager), *args], check=False)
    raise SystemExit(result.returncode)


@cli.command("route-npm", hidden=True, context_settings={"ignore_unknown_options": True})
@click.argument("manager_args", nargs=-1, type=click.UNPROCESSED)
def route_npm(manager_args):
    """Internal helper used by the optional npm shim."""
    _route_npm_family("npm", list(manager_args))


@cli.command("route-yarn", hidden=True, context_settings={"ignore_unknown_options": True})
@click.argument("manager_args", nargs=-1, type=click.UNPROCESSED)
def route_yarn(manager_args):
    """Internal helper used by the optional yarn shim."""
    _route_npm_family("yarn", list(manager_args))


@cli.command("route-pnpm", hidden=True, context_settings={"ignore_unknown_options": True})
@click.argument("manager_args", nargs=-1, type=click.UNPROCESSED)
def route_pnpm(manager_args):
    """Internal helper used by the optional pnpm shim."""
    _route_npm_family("pnpm", list(manager_args))


if __name__ == "__main__":
    cli()
