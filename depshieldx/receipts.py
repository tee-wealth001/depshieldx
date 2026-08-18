"""Compatibility alias for :mod:`depshieldx.storage.receipts`."""

import sys

from .storage import receipts as _implementation

sys.modules[__name__] = _implementation
