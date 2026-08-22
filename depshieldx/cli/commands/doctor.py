"""`depshieldx doctor` -- a single command surfacing every prerequisite
check this project already performs piecemeal elsewhere (the Python/pip
gate every install/scan run enforces via prerequisites.py, the Docker
daemon check deep mode's own run_sandbox() does lazily on first use, the
host Trivy check trivy.py does lazily on first use, and each ecosystem's
own resolve_*_tool() PATH lookup, otherwise only ever surfaced as a
failure deep inside a real install/scan run) -- so a user can find out
what's missing before running anything real, not from a failure midway
through an install.

Deliberately reuses every check's own existing implementation rather than
re-deriving any of it (the same function real install/scan runs call),
so this can never drift from what actually gates a real run."""

import click

from ...ecosystems.cargo.ecosystem import resolve_cargo_tool
from ...ecosystems.composer.ecosystem import resolve_composer_tool
from ...ecosystems.go.ecosystem import resolve_go_tool
from ...ecosystems.maven.ecosystem import resolve_maven_tool
from ...ecosystems.npm.ecosystem import resolve_node_tool
from ...ecosystems.nuget.ecosystem import resolve_dotnet_tool
from ...ecosystems.pub.ecosystem import resolve_dart_tool
from ...ecosystems.rubygems.ecosystem import resolve_bundle_tool
from ...security.sandbox.runner import _docker_daemon_available
from ...security.trivy import _is_trivy_installed
from ..output import EXIT_BLOCKED
from ..prerequisites import _runtime_environment_report

# (ecosystem key, resolver function *name*, tool name) -- mirrors each
# ecosystem's own real call site exactly (e.g. rubygems/ecosystem.py's
# resolve_bundle_tool("bundle")), not re-derived independently. Looked up
# by name (via globals()) at call time below, not stored as a direct
# function reference here -- a module-level reference would freeze in the
# real resolver at import time, unpatchable by tests mocking this module's
# own resolve_*_tool attributes afterward.
_ECOSYSTEM_TOOLCHAINS = [
    ("npm", "resolve_node_tool", "npm"),
    ("cargo", "resolve_cargo_tool", "cargo"),
    ("go", "resolve_go_tool", "go"),
    ("maven", "resolve_maven_tool", "mvn"),
    ("nuget", "resolve_dotnet_tool", "dotnet"),
    ("pub", "resolve_dart_tool", "dart"),
    ("rubygems", "resolve_bundle_tool", "bundle"),
    ("composer", "resolve_composer_tool", "composer"),
]


def _status_line(label: str, ok: bool, detail: str = "") -> str:
    marker = click.style("OK", fg="green") if ok else click.style("MISSING", fg="yellow")
    line = f"  {label:<28} {marker}"
    if detail and not ok:
        line += f"  ({detail})"
    return line


@click.command()
def doctor():
    """Check runtime prerequisites and available toolchains."""
    environment = _runtime_environment_report()
    docker_ok, docker_detail = _docker_daemon_available()
    trivy_ok = _is_trivy_installed()

    click.echo("Runtime (required for every operation):")
    click.echo(
        _status_line(
            f"Python {environment['python']['version']} (need {environment['python']['required']})",
            environment["python"]["ok"],
        )
    )
    pip_label = f"pip {environment['pip']['version'] or 'not found'} (need {environment['pip']['required']})"
    click.echo(_status_line(pip_label, environment["pip"]["ok"], environment["pip"]["error"] or ""))

    click.echo("")
    click.echo("Deep mode (Docker sandbox + Trivy scan -- optional, only needed for --deep):")
    click.echo(_status_line("Docker", docker_ok, docker_detail or ""))
    click.echo(_status_line("Trivy", trivy_ok, "not found on PATH" if not trivy_ok else ""))

    click.echo("")
    click.echo("Ecosystem toolchains (only needed for ecosystems you actually use):")
    click.echo(_status_line("pypi (pip)", environment["pip"]["ok"], environment["pip"]["error"] or ""))
    for ecosystem_key, resolver_name, tool_name in _ECOSYSTEM_TOOLCHAINS:
        try:
            globals()[resolver_name](tool_name)
            click.echo(_status_line(f"{ecosystem_key} ({tool_name})", True))
        except RuntimeError as exc:
            click.echo(_status_line(f"{ecosystem_key} ({tool_name})", False, str(exc)))

    if not environment["block"]:
        return
    click.echo("")
    click.secho(f"Blocked: {environment['reason']}", fg="red")
    raise SystemExit(EXIT_BLOCKED)


def register(cli):
    cli.add_command(doctor)
