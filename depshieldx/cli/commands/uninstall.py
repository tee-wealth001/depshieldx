import click

from ...ecosystems import PYPI_ECOSYSTEM
from ..engine import _ecosystem_for_input_source, _load_cli_input, _run_cli_command, _uninstall_args_for_input_source
from ..output import _echo_success, _stage_loader


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


def register(cli):
    cli.command()(uninstall)
