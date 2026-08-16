"""Owns the root Click group.

A leaf module with no dependency on cli/__init__.py or cli/commands/, so
command modules can `from ..app import cli` to register themselves without
importing a partially-initialized package __init__.py.
"""

import click


@click.group()
def cli():
    pass
