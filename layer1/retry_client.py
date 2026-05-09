"""Shared retry client for all external API calls (Rule 4: all external calls idempotent + retryable)."""
import time
import random
import logging
from typing import Callable, TypeVar, Any

logger = logging.getLogger(__name__)

T = TypeVar("T")


def with_retry(
    fn: Callable[[], T],
    *,
    max_attempts: int = 4,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: tuple = (Exception,),
    label: str = "operation",
) -> T:
    """
    Exponential backoff with full jitter.
    Raises the last exception if all attempts are exhausted.
    """
    attempt = 0
    while True:
        try:
            return fn()
        except exceptions as exc:
            attempt += 1
            if attempt >= max_attempts:
                logger.error(
                    "retry_exhausted label=%s attempts=%d error=%s",
                    label, attempt, exc,
                )
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            jitter = random.uniform(0, delay)
            logger.warning(
                "retry_attempt label=%s attempt=%d/%d delay=%.2fs error=%s",
                label, attempt, max_attempts, jitter, exc,
            )
            time.sleep(jitter)
