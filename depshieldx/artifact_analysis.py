"""Compatibility alias for :mod:`depshieldx.security.artifact_analysis`."""

import sys

from .security import artifact_analysis as _implementation

sys.modules[__name__] = _implementation
