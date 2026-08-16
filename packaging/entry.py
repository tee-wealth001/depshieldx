"""PyInstaller entry point.

Deliberately a real top-level script, not depshieldx/cli/__main__.py -- when
PyInstaller analyzes an entry script, it runs as a bare top-level module
(no package context), so __main__.py's `from . import cli` (a relative
import) fails with "attempted relative import with no known parent package".
Reproduced directly during development; this file's absolute import avoids
the problem entirely.
"""

from depshieldx.cli import cli

if __name__ == "__main__":
    cli()
