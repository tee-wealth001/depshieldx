from pathlib import Path
import os
import subprocess

import click

from ...ecosystems import resolve_node_tool
from ...routing import disable_routing as disable_routing_shim, enable_routing as enable_routing_shim, get_routing_status
from ...runtime import pip_command, self_invoke_command
from ..engine import _show_routing_enabled_message


@click.group()
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
    # Only intercept a bare "install"/"i"/"ci" with no specific package named.
    if not args or args[0] not in ("install", "i", "ci"):
        return False
    return all(arg.startswith("-") for arg in args[1:])


def _extract_simple_npm_family_install_targets(args):
    # Mirrors _extract_simple_install_target's pip equivalent: only intercept
    # "install"/"i" naming one or more specific packages, no other flags, so
    # anything ambiguous (e.g. "-g", "--save-dev") passes through untouched.
    if not args or args[0] not in ("install", "i"):
        return None
    targets = [arg for arg in args[1:] if not arg.startswith("-")]
    if not targets or len(targets) != len(args[1:]):
        return None
    return targets


def _route_npm_family(manager, args):
    lockfile_name = NPM_FAMILY_LOCKFILES[manager]
    lockfile_path = Path.cwd() / lockfile_name
    if _is_plain_npm_family_install(args) and lockfile_path.exists():
        click.echo(f"Routing {manager} install through depshieldx...")
        command = self_invoke_command(["install", "--lockfile", str(lockfile_path)])
        result = subprocess.run(command, check=False)
        raise SystemExit(result.returncode)

    if manager == "npm":
        package_targets = _extract_simple_npm_family_install_targets(args)
        if package_targets:
            click.echo(f"Routing {manager} install through depshieldx...")
            command = self_invoke_command(["install", *package_targets, "--ecosystem", "npm"])
            result = subprocess.run(command, check=False)
            raise SystemExit(result.returncode)

    click.secho(
        f"depshieldx routing only intercepts a plain '{manager} install' when {lockfile_name} is present, "
        f"or '{manager} install <package...>' for new packages. Passing through to {manager}.",
        fg="yellow",
        err=True,
    )
    result = subprocess.run([resolve_node_tool(manager), *args], check=False)
    raise SystemExit(result.returncode)


@click.argument("manager_args", nargs=-1, type=click.UNPROCESSED)
def route_npm(manager_args):
    """Internal helper used by the optional npm shim."""
    _route_npm_family("npm", list(manager_args))


@click.argument("manager_args", nargs=-1, type=click.UNPROCESSED)
def route_yarn(manager_args):
    """Internal helper used by the optional yarn shim."""
    _route_npm_family("yarn", list(manager_args))


@click.argument("manager_args", nargs=-1, type=click.UNPROCESSED)
def route_pnpm(manager_args):
    """Internal helper used by the optional pnpm shim."""
    _route_npm_family("pnpm", list(manager_args))


def register(cli):
    cli.add_command(routing)
    cli.command("route-pip", hidden=True, context_settings={"ignore_unknown_options": True})(route_pip)
    cli.command("route-npm", hidden=True, context_settings={"ignore_unknown_options": True})(route_npm)
    cli.command("route-yarn", hidden=True, context_settings={"ignore_unknown_options": True})(route_yarn)
    cli.command("route-pnpm", hidden=True, context_settings={"ignore_unknown_options": True})(route_pnpm)
