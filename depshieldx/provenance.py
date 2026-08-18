"""Compatibility alias for :mod:`depshieldx.security.provenance`."""

import sys

from .security import provenance as _implementation

sys.modules[__name__] = _implementation
