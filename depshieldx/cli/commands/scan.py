import click

from ..engine import (
    _ecosystem_for_input_source,
    _handle_resolution_failure,
    _handle_unexpected_command_error,
    _load_cli_input,
    _resolve_input_source,
    _run_deep_flow,
    _run_fast_flow,
)
from ..output import _echo_step, _stage_loader, set_json_only_output
from ..prerequisites import _enforce_runtime_prerequisites
from ..report import _build_report, _record_resolution


@click.argument("targets", nargs=-1)
@click.option("-r", "--requirement", "requirement_file", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Scan packages from a requirements file")
@click.option("--lockfile", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Scan packages from a lockfile such as uv.lock")
@click.option("--pyproject", "pyproject_file", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str), help="Scan dependencies from a pyproject.toml file")
@click.option(
    "--ecosystem",
    "ecosystem_option",
    type=click.Choice(["pypi", "npm", "cargo", "go", "maven", "nuget", "pub", "rubygems"], case_sensitive=False),
    default=None,
    help="Ecosystem for bare package-name targets (ignored for --lockfile, which is auto-detected by filename). Defaults to pypi.",
)
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
def scan(targets, requirement_file, lockfile, pyproject_file, ecosystem_option, fast, deep, no_cache, verbose, full_report, output_mode):
    """Scan one or more packages without installing them."""
    if fast and deep:
        raise click.UsageError("Use only one of --fast or --deep")
    if full_report and output_mode == "summary":
        output_mode = "both"

    set_json_only_output(output_mode == "json")

    mode = "deep" if deep else "fast"
    input_source = _load_cli_input(
        targets,
        requirement_file=requirement_file,
        lockfile=lockfile,
        pyproject_file=pyproject_file,
        ecosystem=ecosystem_option,
    )
    package_name = input_source.label
    ecosystem = _ecosystem_for_input_source(input_source)

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
                ecosystem=ecosystem,
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


def register(cli):
    cli.command()(scan)
