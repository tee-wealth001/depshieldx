"""Compatibility alias for :mod:`depshieldx.storage.cache`."""

import sys

from .storage import cache as _implementation

sys.modules[__name__] = _implementation
