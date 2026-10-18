"""
ArcP: Autonomous Radial Context Pipeline
Entry Point & CLI Controller
Author: Rahul Chandra Padamuttam (RCP)
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import time

# Ensure QT_QPA_PLATFORM offscreen is NEVER set outside of pytest
if os.environ.get("QT_QPA_PLATFORM") == "offscreen":
    del os.environ["QT_QPA_PLATFORM"]

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QApplication

from core.mime_router import MimeMode
from ui.radial_window import RadialWindow


def run_demo_sequence(window: RadialWindow) -> None:
    """Automated visual showcase rotating through all 7 polymorphic modes."""
    modes = [
        (MimeMode.CODE_LOG, "Log & Secret Scrub Mode", "2026-10-18 ERROR [auth] AWS_KEY=AKIAIOSFODNN7EXAMPLE login failed for root"),
        (MimeMode.DATASET, "Dataset & Synthetic Twin Mode", "user_id,email,age,salary\n101,alice@corp.internal,32,95000\n102,bob@corp.internal,28,78000"),
        (MimeMode.INFRA, "Infra & Container Audit Mode", "FROM python:latest\nUSER root\nEXPOSE 22\nCMD [\"python\", \"app.py\"]"),
        (MimeMode.IMAGE, "CV Smart Blur & Stego Nuke Mode", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x90\x91h6"),
        (MimeMode.ML_MODEL, "ML Opcode & Architecture Mode", b"PK\x03\x04model.pt"),
        (MimeMode.BINARY, "Binary Header X-Ray Mode", b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00"),
        (MimeMode.GIT_PATCH, "Git Instant Diff & Gatekeeper Mode", "diff --git a/core.py b/core.py\n--- a/core.py\n+++ b/core.py\n@@ -1,3 +1,3 @@\n-print('debug')\n+logger.info('ready')\n"),
    ]

    step_index = 0

    def _next_demo_step() -> None:
        nonlocal step_index
        if step_index < len(modes):
            mode, title, sample_data = modes[step_index]
            window.set_active_mode(mode)
            window.show_toast(f"🌟 Demo: {title} ({mode.value})")

            # Simulate hover bloom on slice 1 or 4
            window.hovered_slice_id = 1
            window.hovered_zone = "PRIMARY"
            window.anim_ctrl.request_bloom_for_slice(1)

            step_index += 1
            QTimer.singleShot(2500, _next_demo_step)
        else:
            window.show_toast("✅ Demo Showcase Complete • Ready for Drops")
            window.hovered_slice_id = None
            window.hovered_zone = "VOID"
            window.anim_ctrl.cancel_bloom()

    # Expand HUD first, then start showcase
    screen = QApplication.primaryScreen()
    center_pos = screen.availableGeometry().center() if screen else None
    window.expand_hud(center_pos)
    QTimer.singleShot(800, _next_demo_step)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="arcp",
        description="ArcP: 60-FPS Frameless Polymorphic Radial Desktop Firewall & In-Memory Pipeline",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Start minimized as floating edge seed with global hotkey (Ctrl+Shift+Space) & shake detection",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run automated visual showcase of all 7 polymorphic modes",
    )

    args = parser.parse_args()

    # Enable High-DPI scaling
    if hasattr(Qt, "HighDpiScaleFactorRoundingPolicy"):
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

    from ui.radial_window import RadialWindow, create_arcp_icon

    # Initialize QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    app.setApplicationName("ArcP")
    app.setApplicationDisplayName("ArcP Radial HUD")
    app.setWindowIcon(create_arcp_icon())

    # Graceful Ctrl+C handling
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    sigint_timer = QTimer()
    sigint_timer.start(500)
    sigint_timer.timeout.connect(lambda: None)

    # Determine start state
    start_collapsed = args.daemon and not args.demo
    window = RadialWindow(start_collapsed=start_collapsed)

    # Force into EXPANDED state centered on primary screen when not in daemon mode
    if not start_collapsed:
        screen = QApplication.primaryScreen()
        center_pos = screen.availableGeometry().center() if screen else None
        window.expand_hud(center_pos)
    else:
        window.collapse_to_seed()

    window.show()
    window.raise_()
    window.activateWindow()

    print(f"ArcP HUD launched at ({window.x()}, {window.y()})", flush=True)

    if args.demo:
        run_demo_sequence(window)

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
