"""Shared install/scan/uninstall orchestration -- the flow logic that isn't
specific to any one Click command (resolution, fast/deep checks, host
install, and the routing-shim prompt that fires when depshieldx installs
itself)."""

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import click
import requests

from ..ecosystems import PYPI_ECOSYSTEM, ecosystem_for_name
from ..ecosystems.base import _normalize_name_for_ecosystem, _strip_version_spec
from ..core.input_sources import load_input_source
from ..core.routing import (
    dismiss_routing_prompt,
    disable_routing as disable_routing_shim,
    enable_routing as enable_routing_shim,
    get_routing_status,
    should_prompt_for_routing,
)
from ..security.sandbox.runner import run_sandbox
from ..security.scanner import scan_vulnerabilities
from .output import (
    _echo_error,
    _echo_success,
    _echo_step,
    _emit_result_messages,
    _finish,
    _package_name_from_requirement,
    _stage_loader,
)


def _run_cli_command(command, verbose=False):
    return subprocess.run(
        command,
        check=True,
        capture_output=not verbose,
        text=not verbose,
    )


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


def _load_cli_input(targets, requirement_file=None, lockfile=None, pyproject_file=None, ecosystem=None):
    try:
        return load_input_source(
            targets,
            requirement_file=requirement_file,
            lockfile=lockfile,
            pyproject_file=pyproject_file,
            ecosystem=ecosystem,
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


def _uninstall_args_for_input_source(input_source, ecosystem):
    if input_source.source_type == "requirements":
        return input_source.pip_args[:]

    if input_source.source_type == "lockfile" and ecosystem.name in ("npm", "cargo", "go"):
        # npm/yarn/pnpm, Cargo, and go.sum lockfiles pass their raw path
        # through as the sole requested target (each ecosystem's resolve()
        # reads the lockfile/its sibling manifest directly) -- unlike
        # uv.lock, which is pre-parsed into name==version strings by
        # input_sources.py, so this only applies to ecosystems whose own
        # adapter reads the lockfile itself.
        return ecosystem.direct_dependency_names_for_lockfile(input_source.requested_targets[0])

    package_names = []
    seen = set()
    for target in input_source.requested_targets:
        if ecosystem.name in ("npm", "cargo", "go", "maven"):
            # _package_name_from_requirement is PyPI-shaped (name==version,
            # name[extra]) and actively rejects anything containing "/",
            # which would break scoped npm packages like "@babel/core" --
            # and every Go module path (e.g. "github.com/pkg/errors").
            # npm's/cargo's/go's own "name@version" stripping already
            # exists in ecosystems/base.py and handles this correctly per
            # ecosystem. Maven coordinates ("groupId:artifactId:version")
            # get the same treatment for the same reason.
            package_name = _strip_version_spec(target, ecosystem.name).strip()
        else:
            package_name = _package_name_from_requirement(target) or target.strip()
        if not package_name:
            continue
        normalized = _normalize_name_for_ecosystem(package_name, ecosystem.name)
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
            ecosystem=ecosystem,
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
        source=f"host_{ecosystem.name}",
        ecosystem=ecosystem,
    )
    _finish(report, output_mode)
