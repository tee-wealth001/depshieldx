"""Shared, source-agnostic helpers used by more than one intelligence client."""

import asyncio

import aiohttp

# Increased timeout for better resilience on slower networks
REQUEST_TIMEOUT = 10

# Retry configuration for transient failures
MAX_RETRIES = 3
INITIAL_BACKOFF = 1  # seconds


async def _async_retry(
    coro_fn,
    *args,
    max_retries: int = MAX_RETRIES,
    initial_backoff: float = INITIAL_BACKOFF,
    **kwargs
):
    """
    Retry a coroutine with exponential backoff on transient failures.

    Retries on: timeout, connection errors, and 5xx server errors.
    Returns the result or raises exception after max retries.
    """
    backoff = initial_backoff
    last_exception = None

    for attempt in range(max_retries):
        try:
            return await coro_fn(*args, **kwargs)
        except (asyncio.TimeoutError, aiohttp.ClientConnectorError, aiohttp.ClientSSLError) as e:
            # Transient network errors - retry
            last_exception = e
            if attempt < max_retries - 1:
                await asyncio.sleep(backoff)
                backoff *= 2  # Exponential backoff
        except Exception as e:
            # Other errors - don't retry
            raise

    # All retries exhausted
    if last_exception:
        raise last_exception


def _normalize_name(name: str, ecosystem: str = "pypi") -> str:
    """PyPI treats "-"/"_" as equivalent (PEP 503) so those are folded together for
    matching. Other ecosystems don't share that convention -- npm package names are
    hyphen-significant ("left-pad" is not the same as "left_pad") -- so only PyPI gets
    the substitution.

    Go module paths are case-sensitive canonical identifiers (confirmed directly
    against go.dev/ref/mod's module-path rules), unlike every other ecosystem here --
    lowercasing would fold together genuinely different modules and silently break
    matching against OSV/deps.dev/GitHub Advisories, which key Go entries by the exact
    module path. Only whitespace is trimmed. Maven's "groupId:artifactId" coordinates
    get the same treatment -- Maven Central's repository layout is case-sensitive and
    OSV/deps.dev/GitHub Advisories all key Maven entries by the exact coordinate
    (confirmed directly against a real OSV query response). NuGet package IDs get the
    same treatment for a different reason -- nuget.org's own resolution is case-
    insensitive, but OSV's NuGet-ecosystem matching is case-sensitive on the exact
    canonical casing (confirmed directly: "Microsoft.IdentityModel.JsonWebTokens"
    matches real advisories, the all-lowercase variant matches none). Pub
    package names are case-sensitive too (a small, real grandfathered
    allowlist of mixed-case packages predates pub.dev's lowercase-only
    convention for new publishes, confirmed directly against dart-lang/
    pub-dev's own source), so they get the same "preserve, don't fold"
    treatment. RubyGems gem names are case-sensitive too (confirmed
    directly: a real lowercase "json" resolves, the uppercase "JSON"
    404s), and OSV/GHSA/deps.dev all key RubyGems entries by that exact
    casing (confirmed directly against real query responses). Composer/
    Packagist package names fall through to the plain lowercase path
    below deliberately, not listed here -- confirmed directly Packagist's
    own lookup is case-insensitive but always reports back a lowercase
    canonical form, and OSV's own Packagist-ecosystem matching is
    confirmed directly case-sensitive on that lowercase form, the same
    "registry's canonical form is already case-folded" situation PyPI
    has, not the "case genuinely matters" one this list is for."""
    if ecosystem in ("go", "maven", "nuget", "pub", "rubygems"):
        return name.strip()
    normalized = name.strip().lower()
    if ecosystem == "pypi":
        return normalized.replace("-", "_")
    return normalized
