"""
Solid Matte Inspector Drawer for ArcP.
Frameless, hardware-accelerated diagnostic viewport for rich Markdown,
threat-intel reports, AST audits, and visual tensor inspection.
"""
from __future__ import annotations

import io
from typing import Any, Optional

from PyQt6.QtCore import QPoint, QRect, QSize, Qt, QTimer, pyqtSlot
from PyQt6.QtGui import (
    QColor,
    QFont,
    QImage,
    QKeyEvent,
    QMouseEvent,
    QPixmap,
)
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizeGrip,
    QStackedWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from plugins.base_plugin import PipeResult

DEFAULT_DOCUMENT_CSS = """
body {
    color: #F8FAFC;
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', 'Segoe UI', monospace;
    font-size: 12px;
    line-height: 1.5;
}
h1 {
    color: #00F5D4;
    font-size: 15px;
    font-weight: bold;
    margin-top: 12px;
    margin-bottom: 6px;
    padding-bottom: 4px;
    border-bottom: 1px solid #1E293B;
}
h2 {
    color: #38BDF8;
    font-size: 13.5px;
    font-weight: bold;
    margin-top: 10px;
    margin-bottom: 4px;
}
h3 {
    color: #818CF8;
    font-size: 12.5px;
    font-weight: bold;
    margin-top: 8px;
    margin-bottom: 4px;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin-top: 8px;
    margin-bottom: 8px;
    border: 1px solid #334155;
}
th {
    background-color: #1E293B;
    color: #00F5D4;
    font-weight: bold;
    border: 1px solid #334155;
    padding: 6px 10px;
    text-align: left;
}
td {
    background-color: #0F172A;
    color: #F8FAFC;
    border: 1px solid #1E293B;
    padding: 5px 10px;
}
code {
    background-color: #111827;
    color: #A7F3D0;
    padding: 2px 4px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
}
pre {
    background-color: #111827;
    color: #A7F3D0;
    border: 1px solid #1E293B;
    border-radius: 4px;
    padding: 8px 10px;
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
    line-height: 1.4;
}
ul, ol {
    margin-top: 4px;
    margin-bottom: 4px;
    padding-left: 20px;
}
li {
    color: #E2E8F0;
    margin-bottom: 3px;
}
hr {
    border: none;
    border-top: 1px solid #1E293B;
    margin: 12px 0;
}
"""


class DraggableHeader(QFrame):
    """Header bar supporting smooth drag-to-move across monitors."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self._drag_start_pos: Optional[QPoint] = None

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start_pos = event.globalPosition().toPoint() - self.window().frameGeometry().topLeft()
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if event.buttons() == Qt.MouseButton.LeftButton and self._drag_start_pos is not None:
            self.window().move(event.globalPosition().toPoint() - self._drag_start_pos)
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self._drag_start_pos = None
        super().mouseReleaseEvent(event)


class InspectorDrawer(QWidget):
    """
    Frameless Solid Matte Inspector Drawer for ArcP.
    High-DPI Markdown / code / tensor viewport with 100% opaque obsidian palette.
    """

    WIDTH = 640
    HEIGHT = 560

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        self.setWindowTitle("ArcP Inspector Drawer")
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

        self.resize(self.WIDTH, self.HEIGHT)
        self.setMinimumSize(480, 360)

        # Internal state
        self._raw_content: str = ""
        self._is_raw_view: bool = False
        self._current_image: Optional[QImage] = None
        self._current_action_name: str = "Diagnostic Output"

        self._build_ui()

    def _build_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(10, 10, 10, 10)
        root_layout.setSpacing(0)

        # Outer Solid Frame with 2px border and rounded corners
        self.main_frame = QFrame(self)
        self.main_frame.setObjectName("MainFrame")
        self.main_frame.setStyleSheet("""
            QFrame#MainFrame {
                background-color: #090D16;
                border: 2px solid #334155;
                border-radius: 10px;
            }
        """)
        frame_layout = QVBoxLayout(self.main_frame)
        frame_layout.setContentsMargins(0, 0, 0, 0)
        frame_layout.setSpacing(0)
        root_layout.addWidget(self.main_frame)

        # 1. Top Neon Cyan Accent Strip (2.5px solid #00F5D4)
        self.accent_bar = QFrame(self.main_frame)
        self.accent_bar.setFixedHeight(3)
        self.accent_bar.setStyleSheet("""
            background-color: #00F5D4;
            border: none;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
        """)
        frame_layout.addWidget(self.accent_bar)

        # 2. Draggable Header Bar
        self.header_bar = DraggableHeader(self.main_frame)
        self.header_bar.setFixedHeight(46)
        self.header_bar.setStyleSheet("""
            QFrame {
                background-color: #111827;
                border-bottom: 1px solid #1E293B;
            }
        """)
        header_layout = QHBoxLayout(self.header_bar)
        header_layout.setContentsMargins(14, 0, 12, 0)
        header_layout.setSpacing(10)

        # Mode Pill Badge
        self.mode_badge = QLabel("CODE_LOG", self.header_bar)
        self.mode_badge.setStyleSheet("""
            background-color: #1E293B;
            color: #00F5D4;
            border: 1px solid #334155;
            border-radius: 11px;
            padding: 3px 10px;
            font-family: 'Segoe UI';
            font-size: 11px;
            font-weight: bold;
        """)
        header_layout.addWidget(self.mode_badge)

        # Slice Title
        self.title_label = QLabel("Symbol Audit & Header X-Ray", self.header_bar)
        self.title_label.setStyleSheet("""
            color: #F8FAFC;
            font-family: 'Segoe UI';
            font-size: 13px;
            font-weight: bold;
            border: none;
        """)
        header_layout.addWidget(self.title_label)

        header_layout.addStretch()

        # Latency Badge
        self.latency_badge = QLabel("12.4ms", self.header_bar)
        self.latency_badge.setStyleSheet("""
            background-color: #0F172A;
            color: #94A3B8;
            border: 1px solid #1E293B;
            border-radius: 8px;
            padding: 2px 8px;
            font-family: 'Segoe UI';
            font-size: 11px;
            font-weight: 600;
        """)
        header_layout.addWidget(self.latency_badge)

        # Close Button (✕)
        self.btn_close_header = QPushButton("✕", self.header_bar)
        self.btn_close_header.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_close_header.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #94A3B8;
                border: none;
                font-size: 14px;
                font-weight: bold;
                width: 26px;
                height: 26px;
                border-radius: 13px;
            }
            QPushButton:hover {
                background-color: #EF4444;
                color: #FFFFFF;
            }
        """)
        self.btn_close_header.clicked.connect(self.close)
        header_layout.addWidget(self.btn_close_header)

        frame_layout.addWidget(self.header_bar)

        # 3. Content Viewport (Stacked Widget for Text / Markdown vs Image)
        self.stack = QStackedWidget(self.main_frame)
        self.stack.setStyleSheet("background-color: #090D16; border: none;")

        # Page 0: Markdown / Text Browser
        self.text_browser = QTextBrowser(self.stack)
        self.text_browser.setReadOnly(True)
        self.text_browser.setOpenExternalLinks(True)
        self.text_browser.document().setDefaultStyleSheet(DEFAULT_DOCUMENT_CSS)
        self.text_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #090D16;
                color: #F8FAFC;
                border: none;
                padding: 14px 18px;
                selection-background-color: #6366F1;
                selection-color: #FFFFFF;
            }
            QScrollBar:vertical {
                background: #090D16;
                width: 8px;
                margin: 0px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: #334155;
                min-height: 20px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: #00F5D4;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                background: #090D16;
                height: 8px;
                margin: 0px;
                border: none;
            }
            QScrollBar::handle:horizontal {
                background: #334155;
                min-width: 20px;
                border-radius: 4px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #00F5D4;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
        """)
        self.stack.addWidget(self.text_browser)

        # Page 1: Image Tensor Previewer
        self.image_container = QWidget(self.stack)
        image_layout = QVBoxLayout(self.image_container)
        image_layout.setContentsMargins(16, 16, 16, 16)
        image_layout.setSpacing(10)

        self.image_scroll = QScrollArea(self.image_container)
        self.image_scroll.setWidgetResizable(True)
        self.image_scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_scroll.setStyleSheet("""
            QScrollArea {
                background-color: #0B0F19;
                border: 1px solid #1E293B;
                border-radius: 6px;
            }
            QScrollBar:vertical, QScrollBar:horizontal {
                background: #090D16;
                width: 8px;
                height: 8px;
            }
            QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
                background: #334155;
                border-radius: 4px;
            }
        """)

        self.image_label = QLabel(self.image_scroll)
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setStyleSheet("background-color: transparent;")
        self.image_scroll.setWidget(self.image_label)
        image_layout.addWidget(self.image_scroll)

        self.image_meta_label = QLabel("", self.image_container)
        self.image_meta_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_meta_label.setStyleSheet("color: #94A3B8; font-family: 'Segoe UI'; font-size: 11px;")
        image_layout.addWidget(self.image_meta_label)

        self.stack.addWidget(self.image_container)
        frame_layout.addWidget(self.stack)

        # 4. Interactive Footer Bar
        self.footer_bar = QFrame(self.main_frame)
        self.footer_bar.setFixedHeight(48)
        self.footer_bar.setStyleSheet("""
            QFrame {
                background-color: #111827;
                border-top: 1px solid #1E293B;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
            }
        """)
        footer_layout = QHBoxLayout(self.footer_bar)
        footer_layout.setContentsMargins(14, 0, 14, 0)
        footer_layout.setSpacing(10)

        # Left status stats
        self.status_label = QLabel("Payload Stream Active", self.footer_bar)
        self.status_label.setStyleSheet("""
            color: #94A3B8;
            font-family: 'Segoe UI';
            font-size: 11px;
            border: none;
        """)
        footer_layout.addWidget(self.status_label)

        footer_layout.addStretch()

        # Action Buttons
        button_style = """
            QPushButton {
                background-color: #1E293B;
                color: #F8FAFC;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 14px;
                font-family: 'Segoe UI';
                font-size: 11px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #273549;
                border-color: #00F5D4;
                color: #00F5D4;
            }
            QPushButton:pressed {
                background-color: #1E1B4B;
            }
        """

        # Button 1: Copy to Clipboard
        self.btn_copy = QPushButton("Copy to Clipboard", self.footer_bar)
        self.btn_copy.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_copy.setStyleSheet(button_style)
        self.btn_copy.clicked.connect(self._copy_to_clipboard)
        footer_layout.addWidget(self.btn_copy)

        # Button 2: Toggle Raw / Rendered
        self.btn_toggle_raw = QPushButton("View Raw", self.footer_bar)
        self.btn_toggle_raw.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle_raw.setStyleSheet(button_style)
        self.btn_toggle_raw.clicked.connect(self._toggle_raw_rendered)
        footer_layout.addWidget(self.btn_toggle_raw)

        # Button 3: Close (Esc)
        self.btn_close_footer = QPushButton("Close (Esc)", self.footer_bar)
        self.btn_close_footer.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_close_footer.setStyleSheet(button_style)
        self.btn_close_footer.clicked.connect(self.close)
        footer_layout.addWidget(self.btn_close_footer)

        # Resizing grip in bottom-right corner
        self.size_grip = QSizeGrip(self.footer_bar)
        self.size_grip.setStyleSheet("background-color: transparent;")
        footer_layout.addWidget(self.size_grip)

        frame_layout.addWidget(self.footer_bar)

    def display_result(self, result: PipeResult, anchor_rect: Optional[QRect] = None) -> None:
        """
        Populate the inspector with PipeResult data and bloom next to the Radial HUD.
        """
        self._current_action_name = result.action_name
        self.title_label.setText(result.action_name)
        self.mode_badge.setText(result.mode.value)
        self.latency_badge.setText(f"{result.latency_ms:.1f}ms")

        # Format footer status
        byte_cnt = result.bytes_streamed
        size_str = f"{byte_cnt:,} bytes" if byte_cnt < 1024 * 1024 else f"{byte_cnt / (1024*1024):.2f} MB"
        self.status_label.setText(f"{size_str} streamed • Copied to clipboard")

        # Check if payload is an Image
        is_image = False
        pixmap = QPixmap()

        if isinstance(result.data, QImage):
            pixmap = QPixmap.fromImage(result.data)
            self._current_image = result.data
            is_image = True
        elif isinstance(result.data, QPixmap):
            pixmap = result.data
            self._current_image = result.data.toImage()
            is_image = True
        elif isinstance(result.data, bytes) and any(
            result.data.startswith(sig) for sig in (b"\x89PNG", b"\xff\xd8\xff", b"RIFF", b"GIF8")
        ):
            pixmap.loadFromData(result.data)
            if not pixmap.isNull():
                self._current_image = pixmap.toImage()
                is_image = True

        if is_image and not pixmap.isNull():
            self._current_image = pixmap.toImage()
            self._raw_content = f"Image ({pixmap.width()}x{pixmap.height()}, {len(result.data) if isinstance(result.data, bytes) else 0} bytes)"
            self.btn_toggle_raw.setEnabled(False)
            self.btn_toggle_raw.setText("Image Mode")

            # Scale to fit comfortably
            scaled = pixmap.scaled(
                QSize(560, 420),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self.image_label.setPixmap(scaled)
            self.image_meta_label.setText(
                f"Resolution: {pixmap.width()} × {pixmap.height()} px  •  Format: {result.action_name}  •  High-DPI Ready"
            )
            self.stack.setCurrentIndex(1)
        else:
            self._current_image = None
            self.btn_toggle_raw.setEnabled(True)
            self._raw_content = str(result.data)
            self._is_raw_view = False
            self.btn_toggle_raw.setText("View Raw")

            # Render markdown
            self.text_browser.setMarkdown(self._raw_content)
            self.stack.setCurrentIndex(0)

        # Position cleanly next to Radial HUD
        self._position_near_anchor(anchor_rect)

        self.show()
        self.raise_()
        self.activateWindow()

    def _position_near_anchor(self, anchor_rect: Optional[QRect] = None) -> None:
        """Position cleanly to the right (or left/center) of Radial HUD without overflowing screen."""
        screen = QApplication.primaryScreen()
        avail = screen.availableGeometry() if screen else QRect(0, 0, 1920, 1080)

        w = self.width()
        h = self.height()

        if anchor_rect is not None:
            # Try right side of HUD
            target_x = anchor_rect.right() + 14
            target_y = anchor_rect.center().y() - h // 2

            # Overflow check: flip to left side if right side clips offscreen
            if target_x + w > avail.right():
                target_x = anchor_rect.left() - w - 14

            # If still overflowing or clipped on left, center horizontally
            if target_x < avail.left():
                target_x = avail.center().x() - w // 2

            # Clamp Y coordinate inside screen bounds
            target_y = max(avail.top() + 24, min(target_y, avail.bottom() - h - 24))
            target_x = max(avail.left() + 24, min(target_x, avail.right() - w - 24))
        else:
            # Default centered on screen
            target_x = avail.center().x() - w // 2
            target_y = avail.center().y() - h // 2

        self.move(int(target_x), int(target_y))

    @pyqtSlot()
    def _copy_to_clipboard(self) -> None:
        """Copy active raw payload (text or image) and show visual feedback."""
        cb = QApplication.clipboard()
        if cb:
            if self._current_image is not None and not self._current_image.isNull():
                cb.setImage(self._current_image)
            else:
                cb.setText(self._raw_content)

        # Visual button feedback
        self.btn_copy.setText("Copied ✓")
        self.btn_copy.setStyleSheet("""
            QPushButton {
                background-color: #111827;
                color: #00F5D4;
                border: 1px solid #00F5D4;
                border-radius: 6px;
                padding: 6px 14px;
                font-family: 'Segoe UI';
                font-size: 11px;
                font-weight: bold;
            }
        """)
        QTimer.singleShot(1500, self._restore_copy_button)

    def _restore_copy_button(self) -> None:
        self.btn_copy.setText("Copy to Clipboard")
        self.btn_copy.setStyleSheet("""
            QPushButton {
                background-color: #1E293B;
                color: #F8FAFC;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 14px;
                font-family: 'Segoe UI';
                font-size: 11px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #273549;
                border-color: #00F5D4;
                color: #00F5D4;
            }
            QPushButton:pressed {
                background-color: #1E1B4B;
            }
        """)

    @pyqtSlot()
    def _toggle_raw_rendered(self) -> None:
        """Switch between rendered Markdown view and raw source/text view."""
        if self._current_image is not None:
            return

        self._is_raw_view = not self._is_raw_view
        if self._is_raw_view:
            self.text_browser.setPlainText(self._raw_content)
            self.btn_toggle_raw.setText("View Rendered")
        else:
            self.text_browser.setMarkdown(self._raw_content)
            self.btn_toggle_raw.setText("View Raw")

    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Close drawer instantly when Escape key is pressed."""
        if event.key() == Qt.Key.Key_Escape:
            self.close()
            event.accept()
        else:
            super().keyPressEvent(event)
