import click

from ...receipts import delete_receipts, list_receipts, verify_receipt
from ..output import EXIT_BLOCKED, EXIT_OK


@click.group()
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


def register(cli):
    cli.add_command(receipts)
