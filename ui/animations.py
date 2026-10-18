"""
60-FPS Animation Controllers and Cyberpunk Theme Aesthetics for ArcP.
Provides QVariantAnimation easing for bloom transitions, hover states, and spinning HUD progress rings.
"""
from __future__ import annotations

from typing import Callable, Optional

from PyQt6.QtCore import QEasingCurve, QObject, QTimer, QVariantAnimation, pyqtSignal
from PyQt6.QtGui import QColor, QFont


class CyberpunkPalette:
    """Design System & Cyberpunk Color Palette for ArcP HUD."""
    # Dark glassmorphic background
    SLATE_BG = QColor(15, 23, 42, 220)
    SLATE_HOVER = QColor(30, 41, 59, 245)
    SLATE_ACTIVE = QColor(51, 65, 85, 250)
    GRAVITY_WELL_BG = QColor(10, 15, 29, 235)

    # Neon accents
    NEON_CYAN = QColor(0, 245, 212, 255)
    CYAN_GLOW = QColor(0, 245, 212, 60)
    ELECTRIC_INDIGO = QColor(99, 102, 241, 255)
    INDIGO_DIM = QColor(99, 102, 241, 90)
    AMBER_ALERT = QColor(251, 191, 36, 255)
    ROSE_DANGER = QColor(244, 63, 94, 255)

    # Monospace typography
    TEXT_PRIMARY = QColor(248, 250, 252, 255)
    TEXT_MUTED = QColor(148, 163, 184, 220)
    TEXT_ACCENT = QColor(0, 245, 212, 255)

    @staticmethod
    def get_font(size: int = 9, bold: bool = False) -> QFont:
        font = QFont("Consolas", size)
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setBold(bold)
        return font


class AnimationController(QObject):
    """
    Coordinates 60-FPS continuous HUD spinner animations,
    hover bloom transitions, and delayed tooltip/concentric expansions.
    """
    repaint_needed = pyqtSignal()
    bloom_progress_changed = pyqtSignal(float)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)

        # 1. 60-FPS Spinner Timer (16ms ~ 60 FPS)
        self._spinner_angle: float = 0.0
        self._is_spinning: bool = False
        self._spin_timer = QTimer(self)
        self._spin_timer.setInterval(16)
        self._spin_timer.timeout.connect(self._on_spin_tick)

        # 2. Concentric Ring Bloom Animation
        self._bloom_factor: float = 0.0
        self._bloom_anim = QVariantAnimation(self)
        self._bloom_anim.setDuration(200)
        self._bloom_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._bloom_anim.valueChanged.connect(self._on_bloom_step)

        # 3. Hover Dwell Delay Timer (150ms requirement)
        self._hover_dwell_timer = QTimer(self)
        self._hover_dwell_timer.setSingleShot(True)
        self._hover_dwell_timer.setInterval(150)
        self._pending_slice_id: Optional[int] = None
        self._hover_dwell_timer.timeout.connect(self._on_dwell_timeout)

        # Callback on dwell completion
        self.dwell_triggered: Optional[Callable[[int], None]] = None

    @property
    def spinner_angle(self) -> float:
        return self._spinner_angle

    @property
    def bloom_factor(self) -> float:
        return self._bloom_factor

    def start_spinner(self) -> None:
        """Start spinning the neon progress ring around Gravity Well."""
        self._is_spinning = True
        if not self._spin_timer.isActive():
            self._spin_timer.start()

    def stop_spinner(self) -> None:
        """Stop progress ring animation and reset angle."""
        self._is_spinning = False
        self._spin_timer.stop()
        self._spinner_angle = 0.0
        self.repaint_needed.emit()

    def _on_spin_tick(self) -> None:
        if self._is_spinning:
            self._spinner_angle = (self._spinner_angle + 6.0) % 360.0
            self.repaint_needed.emit()

    def request_bloom_for_slice(self, slice_id: int) -> None:
        """Schedule concentric outer ring bloom after 150ms dwell."""
        if self._pending_slice_id == slice_id and (self._hover_dwell_timer.isActive() or self._bloom_factor > 0.0):
            return
        self._pending_slice_id = slice_id
        self._hover_dwell_timer.start(150)

    def cancel_bloom(self) -> None:
        """Collapse concentric outer ring smoothly."""
        self._hover_dwell_timer.stop()
        self._pending_slice_id = None
        if self._bloom_factor > 0.0:
            self._bloom_anim.stop()
            self._bloom_anim.setStartValue(self._bloom_factor)
            self._bloom_anim.setEndValue(0.0)
            self._bloom_anim.start()

    def _on_dwell_timeout(self) -> None:
        if self._pending_slice_id is not None:
            if self.dwell_triggered:
                self.dwell_triggered(self._pending_slice_id)
            self._bloom_anim.stop()
            self._bloom_anim.setStartValue(self._bloom_factor)
            self._bloom_anim.setEndValue(1.0)
            self._bloom_anim.start()

    def _on_bloom_step(self, val: object) -> None:
        self._bloom_factor = float(val)  # type: ignore
        self.bloom_progress_changed.emit(self._bloom_factor)
        self.repaint_needed.emit()
