"""
Zero-Disk RAM-to-QClipboard byte streamer for ArcP.
Handles instant clipboard synchronization for text, HTML, and images without touching disk.
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union

from PyQt6.QtCore import QByteArray, QMimeData, QObject, pyqtSignal
from PyQt6.QtGui import QClipboard, QImage
from PyQt6.QtWidgets import QApplication


@dataclass
class ClipboardStreamReport:
    """Telemetry report emitted after piping to clipboard."""
    action: str
    latency_ms: float
    bytes_streamed: int
    summary: str
    content_type: str


class ClipboardPipe(QObject):
    """
    Direct in-memory pipe from worker results to the system clipboard.
    Emits a signal for HUD toast notifications.
    """
    streamed = pyqtSignal(ClipboardStreamReport)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)

    def write(
        self,
        payload: Union[str, bytes, QImage, Any],
        action_name: str = "Stream",
        latency_ms: float = 0.0,
        is_html: bool = False,
    ) -> ClipboardStreamReport:
        """
        Stream output directly into system clipboard on the main thread.
        Never writes temporary files to disk.
        """
        app = QApplication.instance()
        clipboard = QApplication.clipboard() if app else None

        bytes_count = 0
        summary_preview = ""
        content_type = "text/plain"

        # 1. QImage Payload
        if isinstance(payload, QImage):
            content_type = "image/png"
            bytes_count = payload.sizeInBytes()
            summary_preview = f"Image ({payload.width()}x{payload.height()} px)"
            if clipboard:
                clipboard.setImage(payload, QClipboard.Mode.Clipboard)

        # 2. Raw Bytes (Check if Image, or UTF-8 Text)
        elif isinstance(payload, (bytes, bytearray)):
            bytes_count = len(payload)
            # Try to load as QImage
            qimg = QImage()
            if qimg.loadFromData(payload):
                content_type = "image/png"
                summary_preview = f"Image ({qimg.width()}x{qimg.height()} px, {bytes_count} bytes)"
                if clipboard:
                    clipboard.setImage(qimg, QClipboard.Mode.Clipboard)
            else:
                try:
                    text_decoded = payload.decode("utf-8")
                    content_type = "text/plain"
                    summary_preview = text_decoded[:60].replace("\n", " ")
                    if clipboard:
                        clipboard.setText(text_decoded, QClipboard.Mode.Clipboard)
                except UnicodeDecodeError:
                    content_type = "application/octet-stream"
                    hex_repr = payload[:32].hex()
                    summary_preview = f"Binary ({bytes_count} bytes) [{hex_repr}...]"
                    if clipboard:
                        clipboard.setText(hex_repr, QClipboard.Mode.Clipboard)

        # 3. String / HTML Payload
        elif isinstance(payload, str):
            bytes_count = len(payload.encode("utf-8", "ignore"))
            summary_preview = payload[:60].replace("\n", " ")
            if is_html or payload.strip().startswith("<!DOCTYPE html") or payload.strip().startswith("<html"):
                content_type = "text/html"
                if clipboard:
                    mime = QMimeData()
                    mime.setHtml(payload)
                    mime.setText(payload)
                    clipboard.setMimeData(mime, QClipboard.Mode.Clipboard)
            else:
                content_type = "text/plain"
                if clipboard:
                    clipboard.setText(payload, QClipboard.Mode.Clipboard)

        # 4. Fallback Object
        else:
            text_val = str(payload)
            bytes_count = len(text_val.encode("utf-8", "ignore"))
            summary_preview = text_val[:60].replace("\n", " ")
            if clipboard:
                clipboard.setText(text_val, QClipboard.Mode.Clipboard)

        report = ClipboardStreamReport(
            action=action_name,
            latency_ms=round(latency_ms, 1),
            bytes_streamed=bytes_count,
            summary=summary_preview,
            content_type=content_type,
        )
        self.streamed.emit(report)
        return report
