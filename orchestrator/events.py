"""In-process pub/sub for pushing dashboard updates via SSE."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

logger = logging.getLogger(__name__)

_subscribers: list[asyncio.Queue[dict[str, Any]]] = []


def notify(event_type: str = "session_update") -> None:
    """Broadcast a lightweight event to all SSE subscribers."""
    payload = {"type": event_type}
    for queue in list(_subscribers):
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            logger.warning("SSE subscriber queue full; dropping event")


async def subscribe() -> AsyncIterator[dict[str, Any]]:
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=64)
    _subscribers.append(queue)
    try:
        while True:
            yield await queue.get()
    finally:
        if queue in _subscribers:
            _subscribers.remove(queue)


def reset_subscribers() -> None:
    """Clear subscribers (tests only)."""
    _subscribers.clear()
