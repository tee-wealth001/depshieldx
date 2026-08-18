"""Compatibility alias for :mod:`depshieldx.core.input_sources`."""

import sys

from .core import input_sources as _implementation

sys.modules[__name__] = _implementation
