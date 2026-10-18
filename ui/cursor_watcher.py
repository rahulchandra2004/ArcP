"""
Cursor Velocity Shake Detector and Global Hotkey Summoner for ArcP.
Summons the radial HUD under cursor upon rapid cursor shaking or Ctrl+Shift+Space.
"""
from __future__ import annotations

import collections
import ctypes
import math
import time
from typing import Deque, Optional, Tuple

from PyQt6.QtCore import QObject, QPoint, QTimer, pyqtSignal
from PyQt6.QtGui import QCursor

try:
    import keyboard  # type: ignore
except ImportError:
    keyboard = None


class CursorWatcher(QObject):
    """
    Watches cursor motion vectors to detect intentional 'shake-to-summon' gestures
    and listens for global hotkey invocation (Ctrl+Shift+Space).
    """
    summon_requested = pyqtSignal(QPoint)
    shake_detected = pyqtSignal(QPoint)

    # Shake parameters: 3 reversals of motion >= 180px/s within 400ms
    SAMPLE_INTERVAL_MS = 25
    MIN_SHAKE_SPEED = 250.0  # pixels/second
    REVERSAL_WINDOW_S = 0.45
    REQUIRED_REVERSALS = 3

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._history: Deque[Tuple[float, int, int]] = collections.deque(maxlen=20)
        self._reversals: Deque[Tuple[float, int]] = collections.deque(maxlen=10)
        self._last_dx_sign = 0

        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(self.SAMPLE_INTERVAL_MS)
        self._poll_timer.timeout.connect(self._sample_cursor)

        self._hotkey_registered = False

    def start(self) -> None:
        """Begin polling cursor positions and register global hotkey hook."""
        self._poll_timer.start()
        if not self._hotkey_registered:
            self._setup_global_hotkey()

    def stop(self) -> None:
        """Stop polling cursor positions."""
        self._poll_timer.stop()

    def _setup_global_hotkey(self) -> None:
        """Register Ctrl+Shift+Space global hotkey hook."""
        if keyboard is not None:
            try:
                keyboard.add_hotkey("ctrl+shift+space", self._on_hotkey_pressed)
                self._hotkey_registered = True
            except Exception:
                self._hotkey_registered = False

    def _on_hotkey_pressed(self) -> None:
        """Triggered from background thread when hotkey is hit."""
        pos = QCursor.pos()
        self.summon_requested.emit(pos)

    def _sample_cursor(self) -> None:
        """Sample cursor coordinate delta and detect rapid horizontal/vertical shakes."""
        now = time.perf_counter()
        pos = QCursor.pos()
        x, y = pos.x(), pos.y()

        if self._history:
            prev_t, prev_x, prev_y = self._history[-1]
            dt = now - prev_t
            if dt > 0.001:
                dx = x - prev_x
                dy = y - prev_y
                dist = math.hypot(dx, dy)
                speed = dist / dt

                if speed >= self.MIN_SHAKE_SPEED and abs(dx) > 8:
                    current_sign = 1 if dx > 0 else -1
                    if self._last_dx_sign != 0 and current_sign != self._last_dx_sign:
                        self._reversals.append((now, current_sign))
                        self._check_reversal_threshold(pos, now)
                    self._last_dx_sign = current_sign

        self._history.append((now, x, y))

    def _check_reversal_threshold(self, pos: QPoint, now: float) -> None:
        """Evaluate if enough rapid reversals occurred within the time window."""
        recent_reversals = [t for t, _ in self._reversals if (now - t) <= self.REVERSAL_WINDOW_S]
        if len(recent_reversals) >= self.REQUIRED_REVERSALS:
            self._reversals.clear()
            self._history.clear()
            self.shake_detected.emit(pos)
            self.summon_requested.emit(pos)
