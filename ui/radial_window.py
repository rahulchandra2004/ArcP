"""
Frameless 60-FPS QPainter Concentric Radial Overlay for ArcP.
Implements the Center Gravity Well, Primary Ring, Outer Concentric Bloom, and Floating Seed.
"""
from __future__ import annotations

import math
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from PyQt6.QtCore import (
    QPoint,
    QPointF,
    QRectF,
    Qt,
    QTimer,
    pyqtSignal,
    pyqtSlot,
)
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QDragEnterEvent,
    QDragLeaveEvent,
    QDragMoveEvent,
    QDropEvent,
    QFont,
    QFontMetrics,
    QIcon,
    QKeyEvent,
    QMouseEvent,
    QPaintEvent,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
    QWheelEvent,
)
from PyQt6.QtWidgets import QApplication, QMenu, QSystemTrayIcon, QWidget


from ui.icons import IconRegistry


def create_arcp_icon() -> QIcon:
    """Generate high-contrast neon cyber ring QIcon in RAM using IconRegistry."""
    return IconRegistry.get_icon("arcp_logo")

from core.clipboard_pipe import ClipboardPipe, ClipboardStreamReport
from core.gravity_well import GravityWell
from core.mime_router import MimeMode, MimeRouter

ORDERED_MODES = [
    MimeMode.IMAGE,
    MimeMode.DATASET,
    MimeMode.CODE_LOG,
    MimeMode.ML_MODEL,
    MimeMode.INFRA,
    MimeMode.BINARY,
    MimeMode.GIT_PATCH,
]
from core.telemetry import TelemetryTracker
from core.token_vault import TokenVault
from core.worker_pool import WorkerPool
from plugins.base_plugin import PipeResult, RadialAction
from plugins.binary_ops import BinaryOpsPlugin
from plugins.code_log_ops import CodeLogOpsPlugin
from plugins.data_ops import DataOpsPlugin
from plugins.git_ops import GitOpsPlugin
from plugins.image_ops import ImageOpsPlugin
from plugins.infra_ops import InfraOpsPlugin
from plugins.ml_ops import MlOpsPlugin
from ui.animations import AnimationController, CyberpunkPalette
from ui.cursor_watcher import CursorWatcher
from ui.geometry import (
    R_CONCENTRIC_INNER,
    R_CONCENTRIC_OUTER,
    R_GRAVITY_WELL,
    R_PRIMARY_INNER,
    R_PRIMARY_OUTER,
    R_TEXT_PRIMARY,
    SLICE_ANGLES,
    build_donut_sector_path,
    polar_to_cartesian,
    resolve_radial_collision,
)


class RadialWindow(QWidget):
    """
    The Master ArcP 60-FPS Concentric Radial HUD.
    Polymorphic, zero-disk, hardware-accelerated QPainter desktop firewall.
    """

    EXPANDED_SIZE = 520
    COLLAPSED_SIZE = 40

    def __init__(self, start_collapsed: bool = False, windowed: bool = False) -> None:
        super().__init__(None)

        self.setWindowTitle("ArcP - Autonomous Radial Context Pipeline")
        self.icon = create_arcp_icon()
        self.setWindowIcon(self.icon)
        self.windowed = windowed

        # 1. Window Flags and Attributes
        if windowed:
            self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowStaysOnTopHint)
            self.setStyleSheet("background-color: #0B0F19; color: #E2E8F0;")
        else:
            flags = Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
            if start_collapsed:
                flags |= Qt.WindowType.Tool
            self.setWindowFlags(flags)
            self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

        self.setAcceptDrops(True)
        self.setMouseTracking(True)

        # 1b. System Tray Integration
        self._tray_icon: Optional[QSystemTrayIcon] = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self._setup_system_tray()

        # 2. Core Subsystems
        self.vault = TokenVault(ttl=600.0)
        self.gravity_well = GravityWell()
        self.telemetry = TelemetryTracker()
        self.clipboard_pipe = ClipboardPipe(self)
        self.worker_pool = WorkerPool()

        # Connect clipboard pipe toast emission
        self.clipboard_pipe.streamed.connect(self._on_clipboard_streamed)

        # Clipboard Auto-Detection: auto-morph radial mode when user copies new data
        cb = QApplication.clipboard()
        if cb:
            cb.dataChanged.connect(self._on_clipboard_data_changed)

        # 3. Polymorphic Plugin Registry
        self.plugins: Dict[MimeMode, RadialAction] = {
            MimeMode.IMAGE: ImageOpsPlugin(),
            MimeMode.DATASET: DataOpsPlugin(),
            MimeMode.CODE_LOG: CodeLogOpsPlugin(self.vault),
            MimeMode.ML_MODEL: MlOpsPlugin(),
            MimeMode.INFRA: InfraOpsPlugin(),
            MimeMode.BINARY: BinaryOpsPlugin(),
            MimeMode.GIT_PATCH: GitOpsPlugin(self.vault),
        }
        self.active_mode: MimeMode = MimeMode.CODE_LOG

        # 4. Animation & Cursor Subsystems
        self.anim_ctrl = AnimationController(self)
        self.anim_ctrl.repaint_needed.connect(self.update)
        self.anim_ctrl.dwell_triggered = self._on_dwell_bloomed

        self.cursor_watcher = CursorWatcher(self)
        self.cursor_watcher.summon_requested.connect(self.summon_under_cursor)
        # Defer cursor watcher & global hotkey hook slightly so HUD paints instantly
        QTimer.singleShot(100, self.cursor_watcher.start)

        # 5. UI State
        self.is_collapsed: bool = start_collapsed
        self.manual_mode_override: bool = False
        self.hovered_slice_id: Optional[int] = None
        self.hovered_sub_slice_idx: Optional[int] = None
        self.hovered_zone: str = "VOID"
        self.active_bloom_slice: Optional[int] = None

        # Floating Toast State
        self._toast_message: Optional[str] = None
        self._toast_icon: Optional[str] = None
        self._toast_timer = QTimer(self)
        self._toast_timer.setSingleShot(True)
        self._toast_timer.timeout.connect(self._hide_toast)

        # Telemetry HUD update timer (every 500ms)
        self._hud_timer = QTimer(self)
        self._hud_timer.setInterval(500)
        self._hud_timer.timeout.connect(self._refresh_hud_telemetry)
        self._hud_timer.start()

        # Initial geometry
        if self.is_collapsed:
            self.resize(self.COLLAPSED_SIZE, self.COLLAPSED_SIZE)
            self._dock_to_screen_edge()
        else:
            self.resize(self.EXPANDED_SIZE, self.EXPANDED_SIZE)
            self._center_on_screen()

    def _center_on_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen:
            center = screen.availableGeometry().center()
            self.move(
                center.x() - self.EXPANDED_SIZE // 2,
                center.y() - self.EXPANDED_SIZE // 2,
            )

    def _dock_to_screen_edge(self) -> None:
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            # Dock to right edge middle
            self.move(geo.x() + geo.width() - self.COLLAPSED_SIZE - 20, geo.y() + geo.height() // 2)

    def _setup_system_tray(self) -> None:
        """Create Windows system tray icon and context menu."""
        tray_menu = QMenu()
        act_show = tray_menu.addAction("Show ArcP HUD")
        act_show.triggered.connect(lambda: self.expand_hud())
        act_clear = tray_menu.addAction("Clear Gravity Well Queue")
        act_clear.triggered.connect(self._clear_queue_from_tray)
        tray_menu.addSeparator()
        act_quit = tray_menu.addAction("Exit ArcP")
        app_inst = QApplication.instance()
        if app_inst:
            act_quit.triggered.connect(app_inst.quit)

        self._tray_icon = QSystemTrayIcon(self.icon, self)
        self._tray_icon.setToolTip("ArcP - Autonomous Radial Context Pipeline")
        self._tray_icon.setContextMenu(tray_menu)
        self._tray_icon.activated.connect(self._on_tray_activated)
        self._tray_icon.show()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            if self.is_collapsed or not self.isVisible():
                self.expand_hud()
            else:
                self.raise_()
                self.activateWindow()

    def _clear_queue_from_tray(self) -> None:
        count = self.gravity_well.clear()
        self.telemetry.set_queue_count(0)
        self.show_toast(f"Cleared {count} queued items")

    # -------------------------------------------------------------------------
    # State Transitions: Collapsed (Floating Seed) <-> Expanded (Bloomed HUD)
    # -------------------------------------------------------------------------
    @pyqtSlot(QPoint)
    def summon_under_cursor(self, cursor_pos: QPoint) -> None:
        """Summons and blooms the radial HUD centered precisely at cursor position."""
        self.expand_hud(cursor_pos)

    def expand_hud(self, center_pos: Optional[QPoint] = None) -> None:
        """Expand from floating seed into full 520x520 HUD."""
        if center_pos is None:
            screen = QApplication.primaryScreen()
            if screen:
                center_pos = screen.availableGeometry().center()
            else:
                center_pos = self.geometry().center()

        self.is_collapsed = False
        self.resize(self.EXPANDED_SIZE, self.EXPANDED_SIZE)
        self.move(center_pos.x() - self.EXPANDED_SIZE // 2, center_pos.y() - self.EXPANDED_SIZE // 2)
        self.show()
        self.raise_()
        self.activateWindow()
        self.update()

    def collapse_to_seed(self) -> None:
        """Collapse HUD to subtle 40x40 floating seed docked at screen edge."""
        self.is_collapsed = True
        self.anim_ctrl.cancel_bloom()
        self.resize(self.COLLAPSED_SIZE, self.COLLAPSED_SIZE)
        self._dock_to_screen_edge()
        self.update()

    def set_active_mode(self, mode: MimeMode, manual: bool = False) -> None:
        """Switch polymorphic mode."""
        if manual:
            self.manual_mode_override = True
        self.active_mode = mode
        self.update()

    def _reclassify_active_content(self) -> None:
        """Re-sniff clipboard payload and auto-shift mode if applicable."""
        cb = QApplication.clipboard()
        mime = cb.mimeData() if cb else None
        if not mime:
            return
        payload = None
        if mime.hasUrls() and mime.urls():
            payload = mime.urls()[0].toLocalFile()
        elif mime.hasImage() and not mime.imageData().isNull():
            payload = mime.imageData()
        elif cb and not cb.image().isNull():
            payload = cb.image()
        elif mime.hasText() and mime.text().strip():
            payload = mime.text()

        if payload is not None and payload != "ArcP Sample Payload":
            detected_mode, _ = MimeRouter.classify_payload(payload)
            self.active_mode = detected_mode

    def _on_clipboard_data_changed(self) -> None:
        """Dynamically detect and morph radial mode when user copies new content to clipboard."""
        if self.manual_mode_override:
            return

        cb = QApplication.clipboard()
        mime = cb.mimeData() if cb else None
        if not mime:
            return

        payload = None
        if mime.hasUrls() and mime.urls():
            payload = mime.urls()[0].toLocalFile()
        elif mime.hasImage() and not mime.imageData().isNull():
            payload = mime.imageData()
        elif cb and not cb.image().isNull():
            payload = cb.image()
        elif mime.hasText() and mime.text().strip():
            payload = mime.text()

        if payload is not None and payload != "ArcP Sample Payload":
            detected_mode, desc = MimeRouter.classify_payload(payload)
            if detected_mode != self.active_mode:
                self.set_active_mode(detected_mode, manual=False)
                self.show_toast(f"Mode Auto-Shift: {detected_mode.value}", icon_name="sparkle")

    # -------------------------------------------------------------------------
    # Drag and Drop Events (<10ms Header Sniffing & Target Routing)
    # -------------------------------------------------------------------------
    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        mime = event.mimeData()
        if not self.manual_mode_override:
            detected_mode, desc = MimeRouter.classify_payload(mime)
            self.active_mode = detected_mode

        if self.is_collapsed:
            pos = self.mapToGlobal(event.position().toPoint())
            self.expand_hud(pos)

        event.acceptProposedAction()
        self.update()

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        pos = event.position()
        self._update_hover_coordinates(pos.x(), pos.y())
        event.acceptProposedAction()

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:
        self.hovered_slice_id = None
        self.hovered_sub_slice_idx = None
        self.hovered_zone = "VOID"
        self.anim_ctrl.cancel_bloom()
        self.update()
        event.accept()

    def dropEvent(self, event: QDropEvent) -> None:
        pos = event.position()
        self._update_hover_coordinates(pos.x(), pos.y())
        mime = event.mimeData()

        # Extract payload representation
        payload: Any = ""
        source_name = "Clipboard Stream"

        if mime.hasUrls() and mime.urls():
            local_path = mime.urls()[0].toLocalFile()
            payload = local_path
            source_name = os.path.basename(local_path)
        elif mime.hasImage():
            payload = mime.imageData()
            source_name = "In-Memory Image"
        elif mime.hasText():
            payload = mime.text()
            source_name = "Text Stream"

        # Check drop zone
        if self.hovered_zone == "GRAVITY_WELL":
            # Deposit into batch queue without execution
            self.gravity_well.enqueue(
                source_name=source_name,
                raw_data=payload,
                mime_mode=self.active_mode.value,
                size_bytes=len(str(payload).encode("utf-8")),
            )
            self.telemetry.set_queue_count(self.gravity_well.count)
            self.show_toast(f"Queued in Gravity Well: {source_name} ({self.gravity_well.count} total)", icon_name="package")
            event.acceptProposedAction()
            self.update()
            return

        elif self.hovered_slice_id in (1, 2, 3, 4):
            # Target action selected
            slice_id = self.hovered_slice_id
            sub_option = None

            plugin = self.plugins.get(self.active_mode)
            if plugin and slice_id in plugin.slices:
                slice_cfg = plugin.slices[slice_id]
                if self.hovered_zone == "CONCENTRIC" and self.hovered_sub_slice_idx is not None:
                    if 0 <= self.hovered_sub_slice_idx < len(slice_cfg.sub_slices):
                        sub_option = slice_cfg.sub_slices[self.hovered_sub_slice_idx].id

            # If Gravity Well has buffered files, process all or dropped
            if not self.gravity_well.is_empty:
                batch = self.gravity_well.dequeue_all()
                self.telemetry.set_queue_count(0)
                # Execute batch sequentially or on primary
                self._dispatch_action(payload, slice_id, sub_option)
                self.show_toast(f"Batch Processing {len(batch)+1} items on Slice {slice_id}", icon_name="zap")
            else:
                self._dispatch_action(payload, slice_id, sub_option)

            event.acceptProposedAction()
            self.update()

    # -------------------------------------------------------------------------
    # Mouse Interaction (Click & Hover)
    # -------------------------------------------------------------------------
    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self.is_collapsed:
            return
        pos = event.position()
        self._update_hover_coordinates(pos.x(), pos.y())

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.RightButton:
            # Show context menu with mode selection and actions
            self._show_context_menu(event.globalPosition().toPoint())
            return

        if self.is_collapsed:
            # Clicking seed blooms HUD
            self.expand_hud(self.mapToGlobal(event.position().toPoint()))
            return

        # Check click on slices or core
        if self.hovered_zone == "GRAVITY_WELL":
            if not self.gravity_well.is_empty:
                cleared = self.gravity_well.clear()
                self.telemetry.set_queue_count(0)
                self.show_toast(f"Cleared {cleared} queued items")
                self.update()
            else:
                # Cycle mode on center core click (manual selection)
                idx = ORDERED_MODES.index(self.active_mode) if self.active_mode in ORDERED_MODES else 0
                new_mode = ORDERED_MODES[(idx + 1) % len(ORDERED_MODES)]
                self.set_active_mode(new_mode, manual=True)
                plugin = self.plugins.get(new_mode)
                name = plugin.name if plugin else new_mode.value
                self.show_toast(f"Mode: {new_mode.value} • {name}", icon_name="sparkle")
            return

        # Check click on primary slices (1, 2, 3, 4) or concentric sub-slices
        if self.hovered_slice_id in (1, 2, 3, 4):
            slice_id = self.hovered_slice_id
            sub_option = None
            plugin = self.plugins.get(self.active_mode)
            if plugin and slice_id in plugin.slices:
                slice_cfg = plugin.slices[slice_id]
                if self.hovered_zone == "CONCENTRIC" and self.hovered_sub_slice_idx is not None:
                    if 0 <= self.hovered_sub_slice_idx < len(slice_cfg.sub_slices):
                        sub_option = slice_cfg.sub_slices[self.hovered_sub_slice_idx].id

            # Priority 1: If items are queued in the Gravity Well, execute them!
            if not self.gravity_well.is_empty:
                batch = self.gravity_well.dequeue_all()
                self.telemetry.set_queue_count(0)
                # Dispatch each queued payload
                for item in batch:
                    self._dispatch_action(item.raw_data, slice_id, sub_option)
                self.show_toast(f"Processing {len(batch)} queued item(s) on Slice {slice_id}", icon_name="zap")
                self.update()
                return

            # Priority 2: Extract active payload from Windows clipboard (files, images, or text)
            payload: Any = None
            cb = QApplication.clipboard()
            mime = cb.mimeData() if cb else None
            if mime is not None:
                if mime.hasUrls() and mime.urls():
                    payload = mime.urls()[0].toLocalFile()
                elif mime.hasImage() and not mime.imageData().isNull():
                    payload = mime.imageData()
                elif cb and not cb.image().isNull():
                    payload = cb.image()
                elif mime.hasText() and mime.text().strip():
                    payload = mime.text()

            # Auto-classify clipboard payload ONLY if manual_mode_override is False!
            if not self.manual_mode_override:
                if payload is not None and payload != "ArcP Sample Payload":
                    detected_mode, _ = MimeRouter.classify_payload(payload)
                    if detected_mode != self.active_mode:
                        self.set_active_mode(detected_mode, manual=False)

            # Priority 3: Fallback mode-appropriate sample if clipboard is completely blank
            if payload is None:
                if self.active_mode == MimeMode.IMAGE:
                    import io
                    from PIL import Image, ImageDraw
                    sample_im = Image.new("RGB", (400, 200), color="#1E293B")
                    d = ImageDraw.Draw(sample_im)
                    d.text((30, 40), "ArcP In-Memory Visual Tensor", fill="#38BDF8")
                    d.text((30, 80), "Zero-Disk Context Pipeline", fill="#F8FAFC")
                    d.text((30, 120), "Copy any screenshot or image (Win+Shift+S)", fill="#94A3B8")
                    buf = io.BytesIO()
                    sample_im.save(buf, format="PNG")
                    payload = buf.getvalue()
                elif self.active_mode == MimeMode.DATASET:
                    payload = "id,name,role,salary\n1,Alice,Engineer,120000\n2,Bob,Architect,140000"
                elif self.active_mode == MimeMode.INFRA:
                    payload = "FROM python:3.11-slim\nUSER root\nEXPOSE 22\nCMD [\"python\", \"app.py\"]"
                elif self.active_mode == MimeMode.GIT_PATCH:
                    payload = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-debug=True\n+debug=False\n"
                elif self.active_mode == MimeMode.BINARY:
                    payload = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40
                elif self.active_mode == MimeMode.ML_MODEL:
                    payload = '{"model_format": "onnx", "input_shape": [1, 3, 224, 224], "layers": 50}'
                else:
                    payload = "2026-10-18 12:00:00 ERROR [auth] AWS_KEY=AKIAIOSFODNN7EXAMPLE login failed for root"
                self.show_toast(f"No clipboard item • Executing {self.active_mode.value} sample", icon_name="info")

            self._dispatch_action(payload, slice_id, sub_option)
            self.update()

    def wheelEvent(self, event: QWheelEvent) -> None:
        """Cycle polymorphic modes with mouse scroll wheel."""
        delta = event.angleDelta().y()
        if delta == 0:
            delta = event.angleDelta().x()
        idx = ORDERED_MODES.index(self.active_mode) if self.active_mode in ORDERED_MODES else 0
        if delta > 0:
            new_mode = ORDERED_MODES[(idx - 1) % len(ORDERED_MODES)]
        else:
            new_mode = ORDERED_MODES[(idx + 1) % len(ORDERED_MODES)]
        self.set_active_mode(new_mode, manual=True)
        plugin = self.plugins.get(new_mode)
        name = plugin.name if plugin else new_mode.value
        self.show_toast(f"Mode: {new_mode.value} • {name}", icon_name="sparkle")
        event.accept()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Switch modes with number keys 1-7, Tab, A/0 to auto-detect, or close with Escape."""
        key = event.key()
        if key == Qt.Key.Key_Tab:
            idx = ORDERED_MODES.index(self.active_mode) if self.active_mode in ORDERED_MODES else 0
            new_mode = ORDERED_MODES[(idx + 1) % len(ORDERED_MODES)]
            self.set_active_mode(new_mode, manual=True)
            self.show_toast(f"Mode: {new_mode.value}", icon_name="sparkle")
        elif Qt.Key.Key_1 <= key <= Qt.Key.Key_7:
            idx = key - Qt.Key.Key_1
            if 0 <= idx < len(ORDERED_MODES):
                self.set_active_mode(ORDERED_MODES[idx], manual=True)
                self.show_toast(f"Mode: {ORDERED_MODES[idx].value}", icon_name="sparkle")
        elif key in (Qt.Key.Key_A, Qt.Key.Key_0):
            self.manual_mode_override = False
            self._reclassify_active_content()
            self.show_toast("Mode: Auto-Detect (MIME Router)", icon_name="sparkle")
            self.update()
        elif key == Qt.Key.Key_Escape:
            self.collapse_to_seed()
        else:
            super().keyPressEvent(event)

    def _show_context_menu(self, global_pos: QPoint) -> None:
        """Sleek Cyberpunk Context Menu with instant mode switching."""
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #0F172A;
                color: #F8FAFC;
                border: 1px solid #00F5D4;
                border-radius: 6px;
                padding: 4px;
                font-family: 'Segoe UI';
                font-size: 12px;
            }
            QMenu::item {
                padding: 6px 20px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #1E293B;
                color: #00F5D4;
            }
            QMenu::separator {
                height: 1px;
                background-color: #334155;
                margin: 4px 8px;
            }
        """)

        # Option 0: Auto-Detect Mode (MIME Router)
        auto_prefix = "[Active] " if not self.manual_mode_override else "         "
        auto_action = menu.addAction(f"{auto_prefix}Auto-Detect Mode (MIME Router)")

        def _enable_auto():
            self.manual_mode_override = False
            self._reclassify_active_content()
            self.show_toast("Mode: Auto-Detect (MIME Router)", icon_name="sparkle")
            self.update()

        auto_action.triggered.connect(_enable_auto)

        menu.addSeparator()

        mode_options = [
            (MimeMode.IMAGE, "Image Ops (JPG, PNG, WebP, OCR)"),
            (MimeMode.DATASET, "Dataset Ops (CSV, Parquet, SQL)"),
            (MimeMode.CODE_LOG, "Code & Log Ops (Secrets, Docker)"),
            (MimeMode.ML_MODEL, "ML Model Ops (ONNX, Tensors)"),
            (MimeMode.INFRA, "Infra Ops (Docker, K8s, Terraform)"),
            (MimeMode.BINARY, "Binary Ops (ELF, PE, Hex X-Ray)"),
            (MimeMode.GIT_PATCH, "Git Patch Ops (Diffs, Commits)"),
        ]

        for mode, title in mode_options:
            is_cur = self.manual_mode_override and (mode == self.active_mode)
            prefix = "[Active] " if is_cur else "         "
            action = menu.addAction(f"{prefix}{title}")
            action.triggered.connect(lambda checked, m=mode: self.set_active_mode(m, manual=True))

        menu.addSeparator()
        collapse_action = menu.addAction("Minimize to Floating Seed")
        collapse_action.triggered.connect(self.collapse_to_seed)

        close_action = menu.addAction("Exit ArcP")
        close_action.triggered.connect(QApplication.instance().quit)

        menu.exec(global_pos)

    def _update_hover_coordinates(self, x: float, y: float) -> None:
        xc = self.width() / 2.0
        yc = self.height() / 2.0

        plugin = self.plugins.get(self.active_mode)
        sub_counts = {}
        if plugin:
            for s_id, s_cfg in plugin.slices.items():
                sub_counts[s_id] = len(s_cfg.sub_slices)

        slice_id, sub_idx, zone = resolve_radial_collision(x, y, xc, yc, sub_counts)

        prev_slice = self.hovered_slice_id
        self.hovered_slice_id = slice_id
        self.hovered_sub_slice_idx = sub_idx
        self.hovered_zone = zone

        if slice_id in (1, 2, 3, 4):
            if sub_counts.get(slice_id, 0) > 0:
                self.anim_ctrl.request_bloom_for_slice(slice_id)
            else:
                self.anim_ctrl.cancel_bloom()
        else:
            if zone != "CONCENTRIC":
                self.anim_ctrl.cancel_bloom()

        if prev_slice != slice_id or zone != self.hovered_zone:
            self.update()

    def _on_dwell_bloomed(self, slice_id: int) -> None:
        self.active_bloom_slice = slice_id
        self.update()

    # -------------------------------------------------------------------------
    # Asynchronous Pipeline Execution
    # -------------------------------------------------------------------------
    def _dispatch_action(self, payload: Any, slice_id: int, sub_option: Optional[str]) -> None:
        plugin = self.plugins.get(self.active_mode)
        if not plugin:
            return

        self.anim_ctrl.start_spinner()

        def _task() -> PipeResult:
            return plugin.execute(payload, slice_id, sub_option)

        worker = self.worker_pool.submit(_task, action_name=f"{plugin.name} S{slice_id}")
        worker.signals.finished.connect(self._on_action_finished)
        worker.signals.error.connect(self._on_action_error)

    @pyqtSlot(object)
    def _on_action_finished(self, result: PipeResult) -> None:
        self.anim_ctrl.stop_spinner()

        # Update telemetry
        self.telemetry.record_latency(result.latency_ms)
        if result.secrets_blocked > 0:
            self.telemetry.increment_secrets_blocked(result.secrets_blocked)

        # Pipe directly to QClipboard on main thread
        self.clipboard_pipe.write(
            payload=result.data,
            action_name=result.action_name,
            latency_ms=result.latency_ms,
            is_html=result.is_html,
        )
        self.update()

    @pyqtSlot(str)
    def _on_action_error(self, err_msg: str) -> None:
        self.anim_ctrl.stop_spinner()
        self.show_toast(f"Execution Error: {err_msg[:60]}", icon_name="cross")
        self.update()

    @pyqtSlot(ClipboardStreamReport)
    def _on_clipboard_streamed(self, report: ClipboardStreamReport) -> None:
        msg = f"{report.action} | {report.latency_ms:.1f}ms | {report.bytes_streamed:,}B -> Clipboard"
        self.show_toast(msg, icon_name="zap")

    def show_toast(self, message: str, icon_name: Optional[str] = None) -> None:
        self._toast_message = message
        self._toast_icon = icon_name
        self._toast_timer.start(3500)
        self.update()

    def _hide_toast(self) -> None:
        self._toast_message = None
        self._toast_icon = None
        self.update()

    def _refresh_hud_telemetry(self) -> None:
        # Trigger repaint for live telemetry updates
        if not self.is_collapsed and self.isVisible():
            self.update()

    # -------------------------------------------------------------------------
    # Master 60-FPS QPainter Rendering Pipeline
    # -------------------------------------------------------------------------
    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

        if self.is_collapsed:
            self._paint_seed(painter)
        else:
            self._paint_expanded_hud(painter)

        painter.end()

    def _paint_seed(self, p: QPainter) -> None:
        """Render floating 40x40 glowing cyber seed."""
        w, h = self.width(), self.height()
        xc, yc = w / 2.0, h / 2.0

        # Background circle
        p.setBrush(QBrush(CyberpunkPalette.GRAVITY_WELL_BG))
        p.setPen(QPen(CyberpunkPalette.ELECTRIC_INDIGO, 2.0))
        p.drawEllipse(QPointF(xc, yc), 16.0, 16.0)

        # Inner neon pulse
        p.setBrush(QBrush(CyberpunkPalette.NEON_CYAN))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QPointF(xc, yc), 5.0, 5.0)

    def _resolve_slice_icon(self, s_info: Any, s_id: int) -> str:
        """Resolve vector icon key for a primary slice."""
        if getattr(s_info, "icon", None):
            return s_info.icon
        name_l = getattr(s_info, "name", "").lower()
        if any(k in name_l for k in ("diff", "conflict", "patch")):
            return "diff"
        if any(k in name_l for k in ("commit", "semantic")):
            return "commit"
        if any(k in name_l for k in ("branch", "rebase")):
            return "git_branch"
        if any(k in name_l for k in ("vram", "cpu", "compute")):
            return "cpu"
        if any(k in name_l for k in ("layer", "tensor", "model", "arch")):
            return "layers"
        if any(k in name_l for k in ("binary", "hex", "byte", "disasm")):
            return "binary"
        if any(k in name_l for k in ("docker", "container", "compose", "compress", "k8s")):
            return "container"
        if any(k in name_l for k in ("terminal", "cli", "script", "wrapper", "env")):
            return "terminal"
        if any(k in name_l for k in ("database", "sql", "table")):
            return "database"
        if any(k in name_l for k in ("hash", "sha", "md5", "crypto")):
            return "hash"
        if any(k in name_l for k in ("scrub", "secret", "blur", "protect", "pii", "gatekeeper", "audit")):
            return "shield"
        if any(k in name_l for k in ("triage", "inspect", "search", "ocr", "ioc", "find")):
            return "search"
        if any(k in name_l for k in ("x-ray", "microscope", "packed", "entropy")):
            return "microscope"
        if any(k in name_l for k in ("eda", "zap", "quick", "speed")):
            return "zap"
        if any(k in name_l for k in ("lock", "vault", "nuke", "exif", "token")):
            return "lock"
        fallback_map = {1: "shield", 2: "search", 3: "sparkle", 4: "container"}
        return fallback_map.get(s_id, "sparkle")

    def _paint_expanded_hud(self, p: QPainter) -> None:
        """Render complete 520x520 100% Solid Matte Industrial Dark HUD."""
        w, h = self.width(), self.height()
        xc, yc = w / 2.0, h / 2.0
        plugin = self.plugins.get(self.active_mode)

        # 1. Outer Concentric Sub-Slices (if bloomed)
        bloom_factor = self.anim_ctrl.bloom_factor
        bloom_slice = self.active_bloom_slice

        if bloom_factor > 0.0 and bloom_slice and plugin and bloom_slice in plugin.slices:
            slice_cfg = plugin.slices[bloom_slice]
            num_subs = len(slice_cfg.sub_slices)
            if num_subs > 0:
                parent_ang = SLICE_ANGLES[bloom_slice]
                sub_span = parent_ang["sweep"] / num_subs
                r_out_current = R_CONCENTRIC_INNER + (R_CONCENTRIC_OUTER - R_CONCENTRIC_INNER) * bloom_factor

                for i, sub in enumerate(slice_cfg.sub_slices):
                    sub_start = (parent_ang["start"] + i * sub_span) % 360.0
                    sub_path = build_donut_sector_path(
                        xc, yc, R_CONCENTRIC_INNER, r_out_current, sub_start, sub_span - 2.0
                    )

                    is_sub_hover = (
                        self.hovered_zone == "CONCENTRIC"
                        and self.hovered_slice_id == bloom_slice
                        and self.hovered_sub_slice_idx == i
                    )
                    fill_color = QColor("#1E1B4B") if is_sub_hover else QColor("#0F172A")
                    border_color = QColor("#6366F1") if is_sub_hover else QColor("#334155")
                    border_width = 2.0 if is_sub_hover else 1.5

                    p.setBrush(QBrush(fill_color))
                    p.setPen(QPen(border_color, border_width))
                    p.drawPath(sub_path)

                    # Text for sub-slice with strict clip path
                    if bloom_factor > 0.5:
                        mid_ang = (sub_start + (sub_span - 2.0) / 2.0) % 360.0
                        scx, scy = polar_to_cartesian(
                            (R_CONCENTRIC_INNER + r_out_current) / 2.0, mid_ang, xc, yc
                        )
                        p.save()
                        p.setClipPath(sub_path)
                        p.setFont(CyberpunkPalette.get_ui_font(7.5, bold=is_sub_hover))
                        p.setPen(QColor("#FFFFFF") if is_sub_hover else QColor("#94A3B8"))
                        p.drawText(
                            QRectF(scx - 38.0, scy - 16.0, 76.0, 32.0),
                            Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
                            sub.name,
                        )
                        p.restore()

        # 2. Inner Primary Ring Slices (Top, Right, Bottom, Left)
        for s_id in (1, 2, 3, 4):
            cfg = SLICE_ANGLES[s_id]
            slice_path = build_donut_sector_path(
                xc, yc, R_PRIMARY_INNER, R_PRIMARY_OUTER, cfg["start"], cfg["sweep"]
            )

            is_hover = (self.hovered_slice_id == s_id and self.hovered_zone == "PRIMARY")
            is_lr = s_id in (2, 4)
            # Left/Right wedges are horizontal: center at 120px for balanced margins from inner/outer walls
            r_centroid = 120.0 if is_lr else R_TEXT_PRIMARY
            cx, cy = polar_to_cartesian(r_centroid, cfg["center"], xc, yc)

            if is_hover:
                # Solid elevated slate with subtle inner radial highlight
                grad = QRadialGradient(QPointF(cx, cy), 90.0)
                grad.setColorAt(0.0, QColor("#283548"))
                grad.setColorAt(1.0, QColor("#1E293B"))
                p.setBrush(QBrush(grad))
                p.setPen(QPen(QColor("#00F5D4"), 2.0))
            else:
                p.setBrush(QBrush(QColor("#111827")))
                p.setPen(QPen(QColor("#334155"), 1.5))

            p.drawPath(slice_path)

            # Sub-Menu Indicator on outer arc if slice has concentric sub-slices
            has_subs = bool(plugin and s_id in plugin.slices and len(plugin.slices[s_id].sub_slices) > 0)
            if has_subs:
                dot_r = R_PRIMARY_OUTER - 7.0  # 168.0px
                dot_color = QColor("#00F5D4") if is_hover else QColor("#475569")
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QBrush(dot_color))
                for dot_offset in (-4.0, 0.0, 4.0):
                    d_ang = (cfg["center"] + dot_offset) % 360.0
                    dx, dy = polar_to_cartesian(dot_r, d_ang, xc, yc)
                    p.drawEllipse(QPointF(dx, dy), 1.8, 1.8)

            # Strict slice clipping for vector icon and typography
            if plugin and s_id in plugin.slices:
                s_info = plugin.slices[s_id]
                p.save()
                p.setClipPath(slice_path)

                # Vector Icon: 20x20px nudged 6px closer to outer arc (cy - 42.0)
                icon_name = self._resolve_slice_icon(s_info, s_id)
                icon_color = QColor("#00F5D4") if is_hover else QColor("#6366F1")
                icon_pix = IconRegistry.get_tinted_pixmap(icon_name, size=20, color=icon_color)
                p.drawPixmap(int(round(cx - 10.0)), int(round(cy - 42.0)), icon_pix)

                # Bounded Text Rectangle (increased height by 12px: 42px -> 54px):
                # Left/Right: QRectF(cx - 48, cy - 18, 96, 54)
                # Top/Bottom: QRectF(cx - 65, cy - 18, 130, 54)
                w_box = 96.0 if is_lr else 130.0

                # 1-Line Bold White Title (#F8FAFC, 9.0pt Bold)
                title_font = CyberpunkPalette.get_ui_font(9.0, bold=True)
                p.setFont(title_font)
                p.setPen(QColor("#F8FAFC"))
                title_rect = QRectF(cx - w_box / 2.0, cy - 18.0, w_box, 16.0)
                p.drawText(
                    title_rect,
                    Qt.AlignmentFlag.AlignCenter,
                    s_info.name,
                )

                # Clean wrapped 1-to-2 line Subtitle (#94A3B8, #E2E8F0 on hover, 7.5pt Medium)
                sub_font = CyberpunkPalette.get_ui_font(7.5, bold=False, weight=QFont.Weight.Medium)
                p.setFont(sub_font)
                p.setPen(QColor("#E2E8F0") if is_hover else QColor("#94A3B8"))
                subtitle_rect = QRectF(cx - w_box / 2.0, cy + 0.0, w_box, 34.0)
                p.drawText(
                    subtitle_rect,
                    Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
                    s_info.description,
                )

                p.restore()

        # 3. Center Gravity Well Core (r < 65px)
        p.setBrush(QBrush(QColor("#090D16")))
        is_gw_hover = (self.hovered_zone == "GRAVITY_WELL")
        gw_border = QColor("#00F5D4") if is_gw_hover else QColor("#334155")
        p.setPen(QPen(gw_border, 2.0))
        p.drawEllipse(QPointF(xc, yc), R_GRAVITY_WELL, R_GRAVITY_WELL)

        # Progress Arc Spinner (around Gravity Well boundary)
        if self.anim_ctrl.spinner_angle > 0.0 or self.worker_pool.active_thread_count > 0:
            spinner_rect = QRectF(
                xc - R_GRAVITY_WELL - 2.0,
                yc - R_GRAVITY_WELL - 2.0,
                (R_GRAVITY_WELL + 2.0) * 2.0,
                (R_GRAVITY_WELL + 2.0) * 2.0,
            )
            spinner_pen = QPen(CyberpunkPalette.NEON_CYAN, 3.0)
            spinner_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(spinner_pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawArc(
                spinner_rect,
                int(self.anim_ctrl.spinner_angle * 16),
                int(90 * 16),
            )

        # 4. Mode Badge inside Solid Pill Background (#1E293B fill, #00F5D4 text)
        if self.manual_mode_override:
            pill_w = 104.0
            pill_rect = QRectF(xc - pill_w / 2.0, yc - 44.0, pill_w, 18.0)
            p.setBrush(QBrush(QColor("#1E293B")))
            p.setPen(QPen(QColor("#00F5D4"), 1.5))
            p.drawRoundedRect(pill_rect, 9.0, 9.0)

            p.setFont(CyberpunkPalette.get_ui_font(6.8, bold=True))
            p.setPen(QColor("#00F5D4"))
            p.drawText(pill_rect, Qt.AlignmentFlag.AlignCenter, f"{self.active_mode.value} • PINNED")
        else:
            pill_w = 76.0
            pill_rect = QRectF(xc - pill_w / 2.0, yc - 44.0, pill_w, 18.0)
            p.setBrush(QBrush(QColor("#1E293B")))
            p.setPen(QPen(QColor("#334155"), 1.0))
            p.drawRoundedRect(pill_rect, 9.0, 9.0)

            p.setFont(CyberpunkPalette.get_ui_font(7.5, bold=True))
            p.setPen(QColor("#00F5D4"))
            p.drawText(pill_rect, Qt.AlignmentFlag.AlignCenter, self.active_mode.value)

        # 5. 7 Solid 4px Pager Dots directly below pill (#00F5D4 active, #334155 inactive)
        dot_y = yc - 18.0
        dot_radius = 2.0
        dot_spacing = 8.0
        start_x = xc - ((len(ORDERED_MODES) - 1) * dot_spacing) / 2.0  # xc - 24.0

        p.setPen(Qt.PenStyle.NoPen)
        for idx, m_mode in enumerate(ORDERED_MODES):
            dot_x = start_x + idx * dot_spacing
            is_active_dot = (m_mode == self.active_mode)
            p.setBrush(QBrush(QColor("#00F5D4") if is_active_dot else QColor("#334155")))
            p.drawEllipse(QPointF(dot_x, dot_y), dot_radius, dot_radius)

        # 6. Center Gravity Well Telemetry HUD
        snap = self.telemetry.snapshot()
        p.setFont(CyberpunkPalette.get_font(7, bold=False))
        p.setPen(CyberpunkPalette.TEXT_PRIMARY)
        p.drawText(
            QRectF(xc - 55.0, yc - 6.0, 110.0, 14.0),
            Qt.AlignmentFlag.AlignCenter,
            f"Latency: {snap.latency_ms:.0f}ms",
        )
        p.setPen(CyberpunkPalette.TEXT_MUTED)
        p.drawText(
            QRectF(xc - 55.0, yc + 8.0, 110.0, 14.0),
            Qt.AlignmentFlag.AlignCenter,
            f"RAM: {snap.ram_mb:.0f}MB",
        )
        p.drawText(
            QRectF(xc - 55.0, yc + 22.0, 110.0, 14.0),
            Qt.AlignmentFlag.AlignCenter,
            f"Blocked: {snap.secrets_blocked}",
        )

        # Queue Count Badge
        q_count = self.gravity_well.count
        q_text = f"{q_count} queued" if q_count > 0 else "Ready"
        p.setFont(CyberpunkPalette.get_font(8, bold=True))
        p.setPen(CyberpunkPalette.AMBER_ALERT if q_count > 0 else CyberpunkPalette.NEON_CYAN)
        p.drawText(
            QRectF(xc - 55.0, yc + 38.0, 110.0, 16.0),
            Qt.AlignmentFlag.AlignCenter,
            q_text,
        )

        # 7. Sleek Floating Toast Overlay
        if self._toast_message:
            toast_rect = QRectF(20.0, h - 45.0, w - 40.0, 32.0)
            p.setBrush(QBrush(QColor("#111827")))
            p.setPen(QPen(CyberpunkPalette.NEON_CYAN, 1.5))
            p.drawRoundedRect(toast_rect, 6.0, 6.0)

            text_rect = toast_rect
            if self._toast_icon:
                icon_pix = IconRegistry.get_pixmap(self._toast_icon, 20)
                if not icon_pix.isNull():
                    p.drawPixmap(int(toast_rect.left() + 10), int(toast_rect.top() + 6), icon_pix)
                    text_rect = QRectF(toast_rect.left() + 34, toast_rect.top(), toast_rect.width() - 44, toast_rect.height())

            p.setFont(CyberpunkPalette.get_font(8, bold=True))
            p.setPen(CyberpunkPalette.TEXT_PRIMARY)
            p.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, self._toast_message)
