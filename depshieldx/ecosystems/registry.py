"""The ecosystem-name -> adapter lookup used by cli.py and input_sources.py."""

from __future__ import annotations

from .base import Ecosystem
from .cargo import CARGO_ECOSYSTEM
from .go import GO_ECOSYSTEM
from .maven import MAVEN_ECOSYSTEM
from .npm import NPM_ECOSYSTEM
from .nuget import NUGET_ECOSYSTEM
from .pypi import PYPI_ECOSYSTEM

ECOSYSTEMS: dict[str, Ecosystem] = {
    PYPI_ECOSYSTEM.name: PYPI_ECOSYSTEM,
    NPM_ECOSYSTEM.name: NPM_ECOSYSTEM,
    CARGO_ECOSYSTEM.name: CARGO_ECOSYSTEM,
    GO_ECOSYSTEM.name: GO_ECOSYSTEM,
    MAVEN_ECOSYSTEM.name: MAVEN_ECOSYSTEM,
    NUGET_ECOSYSTEM.name: NUGET_ECOSYSTEM,
}


def ecosystem_for_name(name: str) -> Ecosystem:
    try:
        return ECOSYSTEMS[name]
    except KeyError:
        raise ValueError(f"unknown ecosystem: {name!r} (known: {sorted(ECOSYSTEMS)})") from None
