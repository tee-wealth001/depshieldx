"""Multi-source CVE/vulnerability lookup.

Queries multiple free vulnerability databases concurrently:
- OSV (covers NVD, GitHub, etc.) -- osv.py
- CISA KEV (Known Exploited Vulnerabilities) -- cisa_kev.py
- deps.dev (Dependency insights and advisories) -- deps_dev.py
- GitHub Advisories (Package security advisories) -- github_advisories.py

Plus a separate, not-currently-wired-in local/URL threat-feed checker --
local_feed.py -- see its module docstring.

fetch_all_sources_for_packages is the one real entry point; everything
else here is this package's own internal wiring.
"""

from .orchestrator import fetch_all_sources_for_packages

__all__ = ["fetch_all_sources_for_packages"]
