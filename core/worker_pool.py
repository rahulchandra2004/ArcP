"""
Asynchronous Worker Pool for ArcP using QThreadPool and QRunnable.
Ensures zero-latency UI responsiveness and non-blocking pipeline execution.
"""
from __future__ import annotations

import sys
import time
import traceback
from typing import Any, Callable, Optional

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal, pyqtSlot


class WorkerSignals(QObject):
    """PyQt signal bus for asynchronous workers."""
    started = pyqtSignal(str)
    progress = pyqtSignal(float, str)
    finished = pyqtSignal(object)  # Emits PipeResult or arbitrary result
    error = pyqtSignal(str)


class AsyncWorker(QRunnable):
    """
    QRunnable wrapper for executing CPU-bound or I/O-bound plugin actions
    off the Qt main thread.
    """

    def __init__(
        self,
        func: Callable[..., Any],
        *args: Any,
        action_name: str = "Execution",
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.action_name = action_name
        self.signals = WorkerSignals()
        self.setAutoDelete(True)

    @pyqtSlot()
    def run(self) -> None:
        """Executes the wrapped task and measures precision latency."""
        start_time = time.perf_counter()
        self.signals.started.emit(self.action_name)

        try:
            result = self.func(*self.args, **self.kwargs)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # If result has a latency_ms attribute, update it
            if hasattr(result, "latency_ms") and getattr(result, "latency_ms", 0.0) <= 0.0:
                setattr(result, "latency_ms", duration_ms)

            self.signals.finished.emit(result)
        except Exception as e:
            err_msg = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
            self.signals.error.emit(err_msg)


class WorkerPool:
    """Manages the background QThreadPool for ArcP actions."""

    def __init__(self, max_threads: Optional[int] = None) -> None:
        self._pool = QThreadPool.globalInstance()
        if max_threads is not None:
            self._pool.setMaxThreadCount(max(1, max_threads))

    @property
    def active_thread_count(self) -> int:
        return self._pool.activeThreadCount()

    @property
    def max_thread_count(self) -> int:
        return self._pool.maxThreadCount()

    def submit(
        self,
        func: Callable[..., Any],
        *args: Any,
        action_name: str = "Action",
        **kwargs: Any,
    ) -> AsyncWorker:
        """Submit a task to the pool and return the active worker."""
        worker = AsyncWorker(func, *args, action_name=action_name, **kwargs)
        self._pool.start(worker)
        return worker
