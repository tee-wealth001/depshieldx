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
    the substitution."""
    normalized = name.strip().lower()
    if ecosystem == "pypi":
        return normalized.replace("-", "_")
    return normalized
