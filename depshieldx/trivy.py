"""Compatibility alias for :mod:`depshieldx.security.trivy`."""

import sys

from .security import trivy as _implementation

sys.modules[__name__] = _implementation
