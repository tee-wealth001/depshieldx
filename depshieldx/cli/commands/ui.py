import click

from ...ui import serve_ui


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


def register(cli):
    cli.command()(ui)
