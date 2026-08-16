"""depshieldx's CLI: entry point for both the console_scripts target
(`depshieldx = "depshieldx.cli:cli"` in pyproject.toml) and `python -m
depshieldx.cli` (used by runtime.py's self_invoke_command for routing
shims -- see __main__.py).

`cli` itself lives in app.py, a leaf module with no dependency on this
file or commands/, so each commands/*.py module can accumulate its Click
parameters independently and only needs `cli` handed to it here, via an
explicit register(cli) call, rather than importing a partially-initialized
package __init__.py.
"""

from .app import cli
from .commands import install, receipts, routing, scan, ui, uninstall

install.register(cli)
scan.register(cli)
uninstall.register(cli)
routing.register(cli)
receipts.register(cli)
ui.register(cli)

__all__ = ["cli"]
