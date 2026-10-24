"""
Generate Clean Portfolio Images of ArcP on a Pure Black Background.
Features ONLY the heading 'ArcP' on top, with the exact ArcP application
rendered in the center at 2x supersampled Retina resolution.
"""
from __future__ import annotations

import os
import shutil
from typing import Tuple

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PIL import Image, ImageDraw, ImageFilter, ImageFont
from PyQt6.QtCore import QPoint, QRect, QSize, Qt
from PyQt6.QtGui import QColor, QFont, QImage, QPainter
from PyQt6.QtWidgets import QApplication

from core.mime_router import MimeMode
from plugins.binary_ops import BinaryOpsPlugin
from ui.inspector_drawer import InspectorDrawer
from ui.radial_window import RadialWindow


def get_system_font(size: int, bold: bool = True) -> ImageFont.FreeTypeFont:
    """Find a modern, clean geometric sans font."""
    font_names = (
        ["segoeuib.ttf", "arialbd.ttf", "calibrib.ttf"]
        if bold
        else ["segoeui.ttf", "arial.ttf", "calibri.ttf"]
    )
    for fn in font_names:
        try:
            return ImageFont.truetype(fn, size)
        except Exception:
            continue
    return ImageFont.load_default()


def render_supersampled_hud(scale_factor: float = 2.0) -> Image.Image:
    """Render the exact ArcP Radial HUD at 2x Retina supersampling."""
    hud = RadialWindow(start_collapsed=False)
    hud.resize(520, 520)
    hud.set_active_mode(MimeMode.BINARY, manual=True)
    hud.hovered_slice_id = 3
    hud.hovered_zone = "PRIMARY"
    hud.anim_ctrl.bloom_progress = 1.0
    hud.active_bloom_slice = 3
    hud.telemetry.record_latency(12.4)

    target_w = int(520 * scale_factor)
    target_h = int(520 * scale_factor)

    qimg = QImage(target_w, target_h, QImage.Format.Format_ARGB32_Premultiplied)
    qimg.fill(0)
    p = QPainter(qimg)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    p.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
    p.scale(scale_factor, scale_factor)
    hud.render(p)
    p.end()

    temp_path = "temp_hud_black.png"
    qimg.save(temp_path)
    im = Image.open(temp_path).convert("RGBA")
    try:
        os.remove(temp_path)
    except Exception:
        pass
    return im


def render_supersampled_drawer(scale_factor: float = 2.0) -> Image.Image:
    """Render the exact ArcP Inspector Drawer with AST audit tables at 2x Retina supersampling."""
    drawer = InspectorDrawer()
    drawer.resize(720, 620)

    py_sample = (
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import sys as system\n"
        "from PyQt6.QtWidgets import QWidget\n"
        "import ctypes\n"
        "\n"
        "MAX_BUFFER_SIZE: int = 1048576\n"
        "DEFAULT_TTL: float = 600.0\n"
        "API_KEY: str = 'AKIAIOSFODNN7EXAMPLE'\n"
        "\n"
        "class PipelineEngine(QWidget):\n"
        "    \"\"\"Zero-disk in-memory context pipeline engine.\"\"\"\n"
        "    def process(self, stream_id: str, timeout: float = 10.0) -> bool:\n"
        "        return True\n"
        "\n"
        "def run_worker(task_id: int) -> int:\n"
        "    url = 'https://api.arcp.local/v1/telemetry'\n"
        "    return task_id\n"
    )
    plugin = BinaryOpsPlugin()
    res = plugin.execute(py_sample, slice_id=3)
    res.latency_ms = 12.4
    drawer.display_result(res)
    drawer.show()

    target_w = int(drawer.width() * scale_factor)
    target_h = int(drawer.height() * scale_factor)

    qimg = QImage(target_w, target_h, QImage.Format.Format_ARGB32_Premultiplied)
    qimg.fill(0)
    p = QPainter(qimg)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    p.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
    p.scale(scale_factor, scale_factor)
    drawer.render(p)
    p.end()

    temp_path = "temp_drawer_black.png"
    qimg.save(temp_path)
    im = Image.open(temp_path).convert("RGBA")
    try:
        os.remove(temp_path)
    except Exception:
        pass
    return im


def generate_exact_hud_black() -> Image.Image:
    """
    Generate the primary exact ArcP Radial HUD on pure black background,
    with ONLY the heading 'ArcP' centered at the top.
    """
    W, H = 2048, 1400
    canvas = Image.new("RGBA", (W, H), (0, 0, 0, 255))
    draw = ImageDraw.Draw(canvas)

    # 1. Heading 'ArcP' on top ONLY
    font_heading = get_system_font(68, bold=True)
    text = "ArcP"
    bbox = draw.textbbox((0, 0), text, font=font_heading)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]

    text_x = (W - text_w) // 2
    text_y = 90

    # Draw pure crisp white title
    draw.text((text_x, text_y), text, font=font_heading, fill=(255, 255, 255, 255))

    # 2. Render Exact ArcP Radial HUD
    hud_im = render_supersampled_hud(scale_factor=2.0)
    # Downscale smoothly to 760x760 for ultra-sharp supersampling
    hud_display_size = 760
    hud_resized = hud_im.resize(
        (hud_display_size, hud_display_size), Image.Resampling.LANCZOS
    )

    # Center in the remaining canvas space below title
    hud_x = (W - hud_display_size) // 2
    hud_y = text_y + text_h + 100

    # Composite exact HUD onto pure black canvas
    canvas.alpha_composite(hud_resized, (hud_x, hud_y))
    return canvas


def generate_exact_combo_black() -> Image.Image:
    """
    Generate the complete ArcP suite (Radial HUD + Inspector Drawer)
    on pure black background, with ONLY the heading 'ArcP' centered at the top.
    """
    W, H = 2560, 1440
    canvas = Image.new("RGBA", (W, H), (0, 0, 0, 255))
    draw = ImageDraw.Draw(canvas)

    # 1. Heading 'ArcP' on top ONLY
    font_heading = get_system_font(72, bold=True)
    text = "ArcP"
    bbox = draw.textbbox((0, 0), text, font=font_heading)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]

    text_x = (W - text_w) // 2
    text_y = 80

    draw.text((text_x, text_y), text, font=font_heading, fill=(255, 255, 255, 255))

    # 2. Render HUD and Drawer
    hud_im = render_supersampled_hud(scale_factor=2.0)
    drawer_im = render_supersampled_drawer(scale_factor=2.0)

    hud_size = 640
    hud_resized = hud_im.resize((hud_size, hud_size), Image.Resampling.LANCZOS)

    # Drawer display size
    drawer_w = 860
    drawer_h = int(drawer_im.size[1] * (drawer_w / drawer_im.size[0]))
    drawer_resized = drawer_im.resize((drawer_w, drawer_h), Image.Resampling.LANCZOS)

    # Calculate horizontal layout side by side
    gap = 80
    total_w = hud_size + gap + drawer_w
    start_x = (W - total_w) // 2

    hud_x = start_x
    drawer_x = start_x + hud_size + gap

    # Center vertically
    center_y = text_y + text_h + (H - (text_y + text_h)) // 2
    hud_y = center_y - hud_size // 2
    drawer_y = center_y - drawer_h // 2

    canvas.alpha_composite(hud_resized, (hud_x, hud_y))
    canvas.alpha_composite(drawer_resized, (drawer_x, drawer_y))
    return canvas


def main() -> None:
    app = QApplication([])
    print("Generating pure black background ArcP showcase images...")

    # 1. Standalone Exact ArcP Radial HUD on Pure Black
    img_hud = generate_exact_hud_black()
    out_hud = "arcp_black.png"
    img_hud.save(out_hud, quality=98)
    print(f"Saved: {out_hud} ({img_hud.size[0]}x{img_hud.size[1]})")

    # 2. Complete ArcP Suite (Radial HUD + Inspector Drawer) on Pure Black
    img_combo = generate_exact_combo_black()
    out_combo = "arcp_combo_black.png"
    img_combo.save(out_combo, quality=98)
    print(f"Saved: {out_combo} ({img_combo.size[0]}x{img_combo.size[1]})")

    # Copy to artifact directory for instant viewing
    artifact_dir = r"C:\Users\Rahul\.gemini\antigravity\brain\b91e6ad2-6800-42bb-b098-fe73727c9d91"
    if os.path.exists(artifact_dir):
        shutil.copy2(out_hud, os.path.join(artifact_dir, out_hud))
        shutil.copy2(out_combo, os.path.join(artifact_dir, out_combo))
        print(f"Copied to artifact directory: {artifact_dir}")


if __name__ == "__main__":
    main()
