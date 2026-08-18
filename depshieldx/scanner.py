"""Compatibility alias for :mod:`depshieldx.security.scanner`."""

import sys

from .security import scanner as _implementation

sys.modules[__name__] = _implementation
