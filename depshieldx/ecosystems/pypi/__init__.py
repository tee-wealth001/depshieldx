"""Compatibility alias for the PyPI ecosystem implementation."""

import sys

from . import ecosystem as _implementation

globals().update(
    {
        name: getattr(_implementation, name)
        for name in dir(_implementation)
        if not name.startswith("__")
    }
)
sys.modules[__name__] = _implementation
