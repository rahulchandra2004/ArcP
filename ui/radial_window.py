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
    QIcon,
    QMouseEvent,
    QPaintEvent,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PyQt6.QtWidgets import QApplication, QMenu, QSystemTrayIcon, QWidget


from ui.icons import IconRegistry


def create_arcp_icon() -> QIcon:
    """Generate high-contrast neon cyber ring QIcon in RAM using IconRegistry."""
    return IconRegistry.get_icon("arcp_logo")

from core.clipboard_pipe import ClipboardPipe, ClipboardStreamReport
from core.gravity_well import GravityWell
from core.mime_router import MimeMode, MimeRouter
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
        self.cursor_watcher.start()

        # 5. UI State
        self.is_collapsed: bool = start_collapsed
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

    def set_active_mode(self, mode: MimeMode) -> None:
        """Switch polymorphic mode."""
        self.active_mode = mode
        self.update()

    # -------------------------------------------------------------------------
    # Drag and Drop Events (<10ms Header Sniffing & Target Routing)
    # -------------------------------------------------------------------------
    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        mime = event.mimeData()
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
            # Right click collapses HUD
            self.collapse_to_seed()
            return

        if self.is_collapsed:
            # Clicking seed blooms HUD
            self.expand_hud(self.mapToGlobal(event.position().toPoint()))
            return

        # Check click on slices
        if self.hovered_zone == "GRAVITY_WELL":
            if not self.gravity_well.is_empty:
                cleared = self.gravity_well.clear()
                self.telemetry.set_queue_count(0)
                self.show_toast(f"Cleared {cleared} queued items")
                self.update()
            else:
                self.collapse_to_seed()
            return

        if self.hovered_slice_id in (1, 2, 3, 4):
            # Execute with current clipboard text
            cb = QApplication.clipboard()
            clip_text = cb.text() if cb else ""
            sub_option = None
            plugin = self.plugins.get(self.active_mode)
            if plugin and self.hovered_slice_id in plugin.slices:
                slice_cfg = plugin.slices[self.hovered_slice_id]
                if self.hovered_zone == "CONCENTRIC" and self.hovered_sub_slice_idx is not None:
                    if 0 <= self.hovered_sub_slice_idx < len(slice_cfg.sub_slices):
                        sub_option = slice_cfg.sub_slices[self.hovered_sub_slice_idx].id

            self._dispatch_action(clip_text or "ArcP Sample Payload", self.hovered_slice_id, sub_option)

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

    def _paint_expanded_hud(self, p: QPainter) -> None:
        """Render complete 520x520 HUD."""
        w, h = self.width(), self.height()
        xc, yc = w / 2.0, h / 2.0
        plugin = self.plugins.get(self.active_mode)

        # 0. Ambient circular dark glass HUD base plate
        p.setBrush(QBrush(QColor(10, 15, 29, 240)))
        p.setPen(QPen(CyberpunkPalette.INDIGO_DIM, 1.5))
        p.drawEllipse(QPointF(xc, yc), 248.0, 248.0)

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
                    sub_path = build_donut_sector_path(xc, yc, R_CONCENTRIC_INNER, r_out_current, sub_start, sub_span - 2.0)

                    is_sub_hover = (
                        self.hovered_zone == "CONCENTRIC"
                        and self.hovered_slice_id == bloom_slice
                        and self.hovered_sub_slice_idx == i
                    )
                    fill_color = CyberpunkPalette.SLATE_ACTIVE if is_sub_hover else CyberpunkPalette.SLATE_BG
                    border_color = CyberpunkPalette.NEON_CYAN if is_sub_hover else CyberpunkPalette.INDIGO_DIM

                    p.setBrush(QBrush(fill_color))
                    p.setPen(QPen(border_color, 1.8 if is_sub_hover else 1.0))
                    p.drawPath(sub_path)

                    # Text for sub-slice
                    if bloom_factor > 0.5:
                        mid_ang = (sub_start + (sub_span - 2.0) / 2.0) % 360.0
                        tx, ty = polar_to_cartesian(
                            (R_CONCENTRIC_INNER + r_out_current) / 2.0, mid_ang, xc, yc
                        )
                        p.setFont(CyberpunkPalette.get_font(8, bold=is_sub_hover))
                        p.setPen(CyberpunkPalette.TEXT_PRIMARY if is_sub_hover else CyberpunkPalette.TEXT_MUTED)
                        p.drawText(
                            QRectF(tx - 40, ty - 12, 80, 24),
                            Qt.AlignmentFlag.AlignCenter,
                            sub.name,
                        )

        # 2. Inner Primary Ring (4 Slices: Top, Right, Bottom, Left)
        for s_id in (1, 2, 3, 4):
            cfg = SLICE_ANGLES[s_id]
            slice_path = build_donut_sector_path(
                xc, yc, R_PRIMARY_INNER, R_PRIMARY_OUTER, cfg["start"], cfg["sweep"]
            )

            is_hover = (self.hovered_slice_id == s_id and self.hovered_zone == "PRIMARY")
            fill_col = CyberpunkPalette.SLATE_HOVER if is_hover else CyberpunkPalette.SLATE_BG
            border_col = CyberpunkPalette.NEON_CYAN if is_hover else CyberpunkPalette.ELECTRIC_INDIGO

            p.setBrush(QBrush(fill_col))
            p.setPen(QPen(border_col, 2.2 if is_hover else 1.2))
            p.drawPath(slice_path)

            # Slice Metadata Text
            if plugin and s_id in plugin.slices:
                s_info = plugin.slices[s_id]
                # Label midpoint radius
                mid_r = (R_PRIMARY_INNER + R_PRIMARY_OUTER) / 2.0
                tx, ty = polar_to_cartesian(mid_r, cfg["center"], xc, yc)

                # Draw Title
                p.setFont(CyberpunkPalette.get_font(9, bold=True))
                p.setPen(CyberpunkPalette.NEON_CYAN if is_hover else CyberpunkPalette.TEXT_PRIMARY)
                p.drawText(
                    QRectF(tx - 65, ty - 16, 130, 18),
                    Qt.AlignmentFlag.AlignCenter,
                    s_info.name,
                )

                # Draw Subtitle
                p.setFont(CyberpunkPalette.get_font(7, bold=False))
                p.setPen(CyberpunkPalette.TEXT_MUTED)
                desc = s_info.description
                if len(desc) > 28:
                    desc = desc[:26] + ".."
                p.drawText(
                    QRectF(tx - 65, ty + 2, 130, 16),
                    Qt.AlignmentFlag.AlignCenter,
                    desc,
                )

        # 3. Center Gravity Well (r < 65px)
        p.setBrush(QBrush(CyberpunkPalette.GRAVITY_WELL_BG))
        is_gw_hover = self.hovered_zone == "GRAVITY_WELL"
        gw_border = CyberpunkPalette.NEON_CYAN if is_gw_hover else CyberpunkPalette.ELECTRIC_INDIGO
        p.setPen(QPen(gw_border, 2.5 if is_gw_hover else 1.5))
        p.drawEllipse(QPointF(xc, yc), R_GRAVITY_WELL, R_GRAVITY_WELL)

        # 4. Progress Arc Spinner (around Gravity Well)
        if self.anim_ctrl.spinner_angle > 0.0 or self.worker_pool.active_thread_count > 0:
            spinner_rect = QRectF(
                xc - R_GRAVITY_WELL - 2,
                yc - R_GRAVITY_WELL - 2,
                (R_GRAVITY_WELL + 2) * 2,
                (R_GRAVITY_WELL + 2) * 2,
            )
            spinner_pen = QPen(CyberpunkPalette.NEON_CYAN, 3.5)
            spinner_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(spinner_pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            # In Qt degrees (1/16th of a degree)
            p.drawArc(
                spinner_rect,
                int(self.anim_ctrl.spinner_angle * 16),
                int(90 * 16),
            )

        # 5. Center Gravity Well Telemetry & Badge Text
        # Mode Badge
        p.setFont(CyberpunkPalette.get_font(9, bold=True))
        p.setPen(CyberpunkPalette.NEON_CYAN)
        p.drawText(
            QRectF(xc - 55, yc - 46, 110, 18),
            Qt.AlignmentFlag.AlignCenter,
            f"[{self.active_mode.value}]",
        )

        # Telemetry HUD
        snap = self.telemetry.snapshot()
        p.setFont(CyberpunkPalette.get_font(7, bold=False))
        p.setPen(CyberpunkPalette.TEXT_PRIMARY)
        p.drawText(
            QRectF(xc - 55, yc - 24, 110, 16),
            Qt.AlignmentFlag.AlignCenter,
            f"Latency: {snap.latency_ms:.0f}ms",
        )
        p.setPen(CyberpunkPalette.TEXT_MUTED)
        p.drawText(
            QRectF(xc - 55, yc - 8, 110, 16),
            Qt.AlignmentFlag.AlignCenter,
            f"RAM: {snap.ram_mb:.0f}MB",
        )
        p.drawText(
            QRectF(xc - 55, yc + 8, 110, 16),
            Qt.AlignmentFlag.AlignCenter,
            f"Blocked: {snap.secrets_blocked}",
        )

        # Queue Count Badge
        q_count = self.gravity_well.count
        q_text = f"{q_count} queued" if q_count > 0 else "Ready"
        p.setFont(CyberpunkPalette.get_font(8, bold=True))
        p.setPen(CyberpunkPalette.AMBER_ALERT if q_count > 0 else CyberpunkPalette.NEON_CYAN)
        p.drawText(
            QRectF(xc - 55, yc + 28, 110, 18),
            Qt.AlignmentFlag.AlignCenter,
            q_text,
        )

        # 6. Sleek Floating Toast Overlay
        if self._toast_message:
            toast_rect = QRectF(20, h - 45, w - 40, 32)
            p.setBrush(QBrush(QColor(15, 23, 42, 245)))
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
