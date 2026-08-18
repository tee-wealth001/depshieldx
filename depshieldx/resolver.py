"""Compatibility alias for :mod:`depshieldx.core.resolver`."""

import sys

from .core import resolver as _implementation

sys.modules[__name__] = _implementation
