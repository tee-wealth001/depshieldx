"""Compatibility alias for :mod:`depshieldx.core.routing`."""

import sys

from .core import routing as _implementation

sys.modules[__name__] = _implementation
