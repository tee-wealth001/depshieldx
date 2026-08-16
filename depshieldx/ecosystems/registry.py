"""The ecosystem-name -> adapter lookup used by cli.py and input_sources.py."""

from __future__ import annotations

from .base import Ecosystem
from .npm import NPM_ECOSYSTEM
from .pypi import PYPI_ECOSYSTEM

ECOSYSTEMS: dict[str, Ecosystem] = {
    PYPI_ECOSYSTEM.name: PYPI_ECOSYSTEM,
    NPM_ECOSYSTEM.name: NPM_ECOSYSTEM,
}


def ecosystem_for_name(name: str) -> Ecosystem:
    try:
        return ECOSYSTEMS[name]
    except KeyError:
        raise ValueError(f"unknown ecosystem: {name!r} (known: {sorted(ECOSYSTEMS)})") from None
