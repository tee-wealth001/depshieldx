"""`depshieldx cache clean` -- physically reclaims disk space neither
cache category otherwise gets back on its own: the provenance cache
already treats an entry as stale past its own 24h logical TTL (see
storage/cache.py's PROVENANCE_CACHE_PRUNE_TTL), but nothing ever deletes
the file itself; the deep-scan bundle cache has no lifecycle policy at
all. Manual-only, like receipts' own `delete`/`delete_receipts` --
deliberately not run automatically on every invocation, so cache
behavior never changes out from under a user without them asking."""

import click

from ...storage.cache import (
    BUNDLE_CACHE_DEFAULT_MAX_AGE_DAYS,
    prune_bundle_cache,
    prune_provenance_cache,
)
from datetime import timedelta


@click.group()
def cache():
    """Manage the local deep-scan bundle and provenance cache."""


@cache.command("clean")
@click.option(
    "--bundle-max-age-days",
    type=int,
    default=BUNDLE_CACHE_DEFAULT_MAX_AGE_DAYS,
    show_default=True,
    help="Remove deep-scan bundle cache entries older than this many days.",
)
def cache_clean(bundle_max_age_days):
    removed_bundles = prune_bundle_cache(max_age=timedelta(days=bundle_max_age_days))
    removed_provenance = prune_provenance_cache()
    click.echo(f"Removed {len(removed_bundles)} bundle cache entr{'y' if len(removed_bundles) == 1 else 'ies'}.")
    click.echo(
        f"Removed {len(removed_provenance)} provenance cache entr{'y' if len(removed_provenance) == 1 else 'ies'}."
    )


def register(cli):
    cli.add_command(cache)
