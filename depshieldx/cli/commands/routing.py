from pathlib import Path
import os
import subprocess

import click

from ...ecosystems import (
    resolve_bundle_tool,
    resolve_cargo_tool,
    resolve_dart_tool,
    resolve_dotnet_tool,
    resolve_go_tool,
    resolve_node_tool,
)
from ...core.routing import disable_routing as disable_routing_shim, enable_routing as enable_routing_shim, get_routing_status
from ...core.runtime import pip_command, self_invoke_command
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


def _extract_simple_cargo_add_targets(args):
    # Mirrors _extract_simple_npm_family_install_targets: only intercept a
    # bare "cargo add <crate...>" with no other flags. depshieldx's cargo
    # "install" support is scoped to `cargo add` specifically (see
    # Cargo / crates.io Support in the README) -- `cargo install` (binary
    # crates) has no depshieldx equivalent and always passes through.
    if not args or args[0] != "add":
        return None
    targets = [arg for arg in args[1:] if not arg.startswith("-")]
    if not targets or len(targets) != len(args[1:]):
        return None
    return targets


@click.argument("cargo_args", nargs=-1, type=click.UNPROCESSED)
def route_cargo(cargo_args):
    """Internal helper used by the optional cargo shim."""
    args = list(cargo_args)
    crate_targets = _extract_simple_cargo_add_targets(args)
    if crate_targets:
        click.echo("Routing cargo add through depshieldx...")
        command = self_invoke_command(["install", *crate_targets, "--ecosystem", "cargo"])
        result = subprocess.run(command, check=False)
        raise SystemExit(result.returncode)

    click.secho(
        "depshieldx routing only intercepts a plain 'cargo add <crate...>' with no other flags. "
        "Passing through to cargo.",
        fg="yellow",
        err=True,
    )
    result = subprocess.run([resolve_cargo_tool("cargo"), *args], check=False)
    raise SystemExit(result.returncode)


def _extract_simple_go_get_targets(args):
    # Mirrors _extract_simple_cargo_add_targets: only intercept a bare
    # "go get <module...>" with no other flags. depshieldx's Go "install"
    # support is scoped to `go get` specifically (see Cargo / crates.io
    # Support's precedent in the README, mirrored for Go) -- `go install`
    # (binary programs) has no depshieldx equivalent and always passes
    # through, the same narrow-minority-of-modules carve-out cargo's
    # binary-crate split is. Since Go 1.18, `go get` never builds or
    # installs anything itself either way -- only go.mod/go.sum management
    # (confirmed directly during the Stage 1 research pass).
    if not args or args[0] != "get":
        return None
    targets = [arg for arg in args[1:] if not arg.startswith("-")]
    if not targets or len(targets) != len(args[1:]):
        return None
    return targets


@click.argument("go_args", nargs=-1, type=click.UNPROCESSED)
def route_go(go_args):
    """Internal helper used by the optional go shim."""
    args = list(go_args)
    module_targets = _extract_simple_go_get_targets(args)
    if module_targets:
        click.echo("Routing go get through depshieldx...")
        command = self_invoke_command(["install", *module_targets, "--ecosystem", "go"])
        result = subprocess.run(command, check=False)
        raise SystemExit(result.returncode)

    click.secho(
        "depshieldx routing only intercepts a plain 'go get <module...>' with no other flags. "
        "Passing through to go.",
        fg="yellow",
        err=True,
    )
    result = subprocess.run([resolve_go_tool("go"), *args], check=False)
    raise SystemExit(result.returncode)


def _extract_simple_dotnet_add_package_target(args):
    # Only intercepts the exact "add package <name>" or "add package
    # <name> --version <version>" shape -- no project positional, no
    # other flags. `dotnet add package` itself supports an optional
    # <PROJECT> positional (before or after "package") and several other
    # flags (--framework, --prerelease, --no-restore, ...) confirmed
    # directly against its own --help output; anything beyond this exact
    # shape passes through untouched rather than risk misinterpreting a
    # real flag combination. depshieldx's own NuGet install support is
    # scoped to exactly one package per invocation anyway (see
    # ecosystems/nuget/ecosystem.py's module docstring for why), so this
    # narrow interception matches what depshieldx can actually route
    # through in one shot.
    if len(args) < 2 or args[0] != "add" or args[1] != "package":
        return None
    remaining = args[2:]
    if not remaining:
        return None
    package_name = remaining[0]
    if package_name.startswith("-"):
        return None
    rest = remaining[1:]
    if not rest:
        return package_name
    if len(rest) == 2 and rest[0] == "--version" and not rest[1].startswith("-"):
        return f"{package_name}@{rest[1]}"
    return None


@click.argument("dotnet_args", nargs=-1, type=click.UNPROCESSED)
def route_dotnet(dotnet_args):
    """Internal helper used by the optional dotnet shim."""
    args = list(dotnet_args)
    package_target = _extract_simple_dotnet_add_package_target(args)
    if package_target:
        click.echo("Routing dotnet add package through depshieldx...")
        command = self_invoke_command(["install", package_target, "--ecosystem", "nuget"])
        result = subprocess.run(command, check=False)
        raise SystemExit(result.returncode)

    click.secho(
        "depshieldx routing only intercepts a plain 'dotnet add package <name>[ --version <version>]' "
        "with no other flags. Passing through to dotnet.",
        fg="yellow",
        err=True,
    )
    result = subprocess.run([resolve_dotnet_tool("dotnet"), *args], check=False)
    raise SystemExit(result.returncode)


def _extract_simple_dart_pub_add_targets(args):
    # Mirrors _extract_simple_cargo_add_targets/_extract_simple_go_get_
    # targets: only intercept a bare "dart pub add <package...>" with no
    # other flags. Unlike `dotnet add package` (confirmed directly to
    # accept only one package per invocation), `dart pub add foo bar`
    # accepts any number of packages in one call (confirmed directly --
    # see ecosystems/pub/ecosystem.py's module docstring), so this
    # mirrors cargo/go's multi-target shim shape, not NuGet's
    # single-target one.
    #
    # `dart pub add` also accepts non-hosted descriptor syntax (`"foo@
    # {path: ../foo}"`, `"foo@{git: ...}"`, `"foo@{hosted: ...}"`,
    # `"foo@{sdk: flutter}"`) and section prefixes (`dev:foo`,
    # `override:foo@1.0.0`) -- confirmed directly against a real `dart
    # pub add --help`. None of these are hosted (pub.dev) package
    # installs depshieldx's own Pub support covers, and confirmed
    # directly the naive "no leading -" filter above would otherwise
    # wrongly capture and mis-parse them (e.g. "dev:foo" as a literal
    # package named "dev:foo"), so any target containing "{" or a
    # recognized section-prefix colon bails out entirely rather than
    # risk misinterpreting it -- the same "don't risk misinterpreting a
    # real shape" caution NuGet's own extractor already uses.
    if len(args) < 2 or args[0] != "pub" or args[1] != "add":
        return None
    remaining = args[2:]
    targets = [arg for arg in remaining if not arg.startswith("-")]
    if not targets or len(targets) != len(remaining):
        return None
    if any("{" in target or target.startswith(("dev:", "override:")) for target in targets):
        return None
    return targets


@click.argument("dart_args", nargs=-1, type=click.UNPROCESSED)
def route_dart(dart_args):
    """Internal helper used by the optional dart shim."""
    args = list(dart_args)
    package_targets = _extract_simple_dart_pub_add_targets(args)
    if package_targets:
        click.echo("Routing dart pub add through depshieldx...")
        command = self_invoke_command(["install", *package_targets, "--ecosystem", "pub"])
        result = subprocess.run(command, check=False)
        raise SystemExit(result.returncode)

    click.secho(
        "depshieldx routing only intercepts a plain 'dart pub add <package...>' with no other flags. "
        "Passing through to dart.",
        fg="yellow",
        err=True,
    )
    result = subprocess.run([resolve_dart_tool("dart"), *args], check=False)
    raise SystemExit(result.returncode)


def _extract_simple_bundle_add_targets(args):
    # Mirrors _extract_simple_cargo_add_targets/_extract_simple_go_get_
    # targets for the common multi-gem, no-flags case, and
    # _extract_simple_dotnet_add_package_target's single-target
    # "--version" shape for the other -- `bundle add gem1 gem2 --version
    # X` applies ONE shared version constraint to EVERY named gem
    # (confirmed directly against real `bundle add` behavior, see
    # ecosystems/rubygems/ecosystem.py's module docstring), so a version
    # flag is only interceptable together with exactly one gem name;
    # anything else (multiple gems with a shared --version, or any other
    # flag) bails out and passes through untouched rather than risk
    # misinterpreting it -- the same "don't risk misinterpreting a real
    # shape" caution NuGet's/Pub's own extractors already use.
    if not args or args[0] != "add":
        return None
    remaining = args[1:]
    if not remaining:
        return None

    if all(not arg.startswith("-") for arg in remaining):
        return list(remaining)

    if (
        len(remaining) == 3
        and not remaining[0].startswith("-")
        and remaining[1] == "--version"
        and not remaining[2].startswith("-")
    ):
        return [f"{remaining[0]}@{remaining[2]}"]

    return None


@click.argument("bundle_args", nargs=-1, type=click.UNPROCESSED)
def route_bundle(bundle_args):
    """Internal helper used by the optional bundle shim."""
    args = list(bundle_args)
    gem_targets = _extract_simple_bundle_add_targets(args)
    if gem_targets:
        click.echo("Routing bundle add through depshieldx...")
        command = self_invoke_command(["install", *gem_targets, "--ecosystem", "rubygems"])
        result = subprocess.run(command, check=False)
        raise SystemExit(result.returncode)

    click.secho(
        "depshieldx routing only intercepts a plain 'bundle add <gem...>' or "
        "'bundle add <gem> --version <version>' with no other flags. Passing through to bundle.",
        fg="yellow",
        err=True,
    )
    result = subprocess.run([resolve_bundle_tool("bundle"), *args], check=False)
    raise SystemExit(result.returncode)


def register(cli):
    cli.add_command(routing)
    cli.command("route-pip", hidden=True, context_settings={"ignore_unknown_options": True})(route_pip)
    cli.command("route-npm", hidden=True, context_settings={"ignore_unknown_options": True})(route_npm)
    cli.command("route-yarn", hidden=True, context_settings={"ignore_unknown_options": True})(route_yarn)
    cli.command("route-pnpm", hidden=True, context_settings={"ignore_unknown_options": True})(route_pnpm)
    cli.command("route-cargo", hidden=True, context_settings={"ignore_unknown_options": True})(route_cargo)
    cli.command("route-go", hidden=True, context_settings={"ignore_unknown_options": True})(route_go)
    cli.command("route-dotnet", hidden=True, context_settings={"ignore_unknown_options": True})(route_dotnet)
    cli.command("route-dart", hidden=True, context_settings={"ignore_unknown_options": True})(route_dart)
    cli.command("route-bundle", hidden=True, context_settings={"ignore_unknown_options": True})(route_bundle)
