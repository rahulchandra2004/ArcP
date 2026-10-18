"""
Gravity Well: Center-core batch queue manager for ArcP.
Buffers dropped items when deposited into the central circular HUD without immediate execution.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, List, Optional


@dataclass
class QueuedPayload:
    """Represents an item buffered in the Gravity Well queue."""
    id: str
    source_name: str
    raw_data: Any
    mime_mode: str
    timestamp: float
    size_bytes: int


class GravityWell:
    """
    Thread-safe FIFO/batch queue for deferred execution in ArcP.
    Items dropped inside the center gravity radius (r < 65px) reside here until triggered.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._queue: List[QueuedPayload] = []
        self._counter: int = 0

    def enqueue(self, source_name: str, raw_data: Any, mime_mode: str = "UNKNOWN", size_bytes: int = 0) -> QueuedPayload:
        """Enqueue an item into the batch queue."""
        with self._lock:
            self._counter += 1
            payload = QueuedPayload(
                id=f"GW_{self._counter:04d}",
                source_name=source_name,
                raw_data=raw_data,
                mime_mode=mime_mode,
                timestamp=time.time(),
                size_bytes=size_bytes,
            )
            self._queue.append(payload)
            return payload

    def enqueue_many(self, items: List[tuple[str, Any, str, int]]) -> List[QueuedPayload]:
        """Enqueue multiple items atomically."""
        with self._lock:
            added = []
            for name, data, mode, size in items:
                added.append(self.enqueue(name, data, mode, size))
            return added

    def dequeue_all(self) -> List[QueuedPayload]:
        """Pop all queued items atomically for batch execution."""
        with self._lock:
            items = list(self._queue)
            self._queue.clear()
            return items

    def peek_all(self) -> List[QueuedPayload]:
        """Inspect all queued items without removing them."""
        with self._lock:
            return list(self._queue)

    def clear(self) -> int:
        """Discard all queued items and return count cleared."""
        with self._lock:
            count = len(self._queue)
            self._queue.clear()
            return count

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def is_empty(self) -> bool:
        with self._lock:
            return len(self._queue) == 0
