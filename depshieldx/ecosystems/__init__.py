"""Ecosystem-neutral package model and per-ecosystem adapters.

Public surface re-exported here unchanged so every existing caller
(`from .ecosystems import ...` / `from depshieldx.ecosystems import ...`,
plus `unittest.mock.patch("depshieldx.ecosystems.PYPI_ECOSYSTEM...")`-style
test patches against the singleton objects and classes below) keeps working
after this module became a package -- see final-plan.md's "Internal
restructuring" section for why and the staged order this is step 1 of.
"""

from .base import Ecosystem, PackageRecord, package_records
from .cargo import CARGO_ECOSYSTEM, CargoEcosystem, resolve_cargo_tool
from .go import GO_ECOSYSTEM, GoEcosystem, resolve_go_tool
from .maven import MAVEN_ECOSYSTEM, MavenEcosystem, resolve_maven_tool
from .npm import NPM_ECOSYSTEM, NpmEcosystem, resolve_node_tool
from .pypi import PYPI_ECOSYSTEM, PyPiEcosystem
from .registry import ECOSYSTEMS, ecosystem_for_name

__all__ = [
    "Ecosystem",
    "PackageRecord",
    "package_records",
    "NPM_ECOSYSTEM",
    "NpmEcosystem",
    "resolve_node_tool",
    "PYPI_ECOSYSTEM",
    "PyPiEcosystem",
    "CARGO_ECOSYSTEM",
    "CargoEcosystem",
    "resolve_cargo_tool",
    "GO_ECOSYSTEM",
    "GoEcosystem",
    "resolve_go_tool",
    "MAVEN_ECOSYSTEM",
    "MavenEcosystem",
    "resolve_maven_tool",
    "ECOSYSTEMS",
    "ecosystem_for_name",
]
