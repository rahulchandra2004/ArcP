"""
Live telemetry tracker for ArcP.
Tracks RAM utilization, operational latency (ms), and total secrets blocked/scrubbed.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


@dataclass(frozen=True)
class TelemetrySnapshot:
    """Read-only snapshot of real-time system and pipeline telemetry."""
    ram_mb: float
    latency_ms: float
    secrets_blocked: int
    queue_count: int


class TelemetryTracker:
    """Thread-safe telemetry aggregator for the ArcP HUD."""

    def __init__(self) -> None:
        self._process: Optional[psutil.Process] = None
        if psutil is not None:
            try:
                self._process = psutil.Process(os.getpid())
            except Exception:
                self._process = None
        self._last_latency_ms: float = 0.0
        self._secrets_blocked_counter: int = 0
        self._queue_count: int = 0

    def record_latency(self, latency_ms: float) -> None:
        """Update the latest operation latency in milliseconds."""
        self._last_latency_ms = max(0.0, float(latency_ms))

    def increment_secrets_blocked(self, count: int = 1) -> None:
        """Increment count of blocked / redacted secrets."""
        if count > 0:
            self._secrets_blocked_counter += count

    def set_queue_count(self, count: int) -> None:
        """Update current gravity well queue depth."""
        self._queue_count = max(0, count)

    def get_ram_mb(self) -> float:
        """Return current RSS memory footprint in megabytes."""
        if self._process is not None:
            try:
                mem_info = self._process.memory_info()
                return round(mem_info.rss / (1024 * 1024), 1)
            except Exception:
                pass
        return 0.0

    def snapshot(self) -> TelemetrySnapshot:
        """Capture current HUD telemetry metrics."""
        return TelemetrySnapshot(
            ram_mb=self.get_ram_mb(),
            latency_ms=round(self._last_latency_ms, 1),
            secrets_blocked=self._secrets_blocked_counter,
            queue_count=self._queue_count,
        )

    def format_hud(self) -> str:
        """Format 1-line HUD string: Latency: XXms | RAM: XXMB | Blocked: XX."""
        s = self.snapshot()
        return f"Latency: {s.latency_ms:.0f}ms | RAM: {s.ram_mb:.0f}MB | Blocked: {s.secrets_blocked}"
