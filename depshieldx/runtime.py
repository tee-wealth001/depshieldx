"""Compatibility alias for :mod:`depshieldx.core.runtime`."""

import sys

from .core import runtime as _implementation

sys.modules[__name__] = _implementation
