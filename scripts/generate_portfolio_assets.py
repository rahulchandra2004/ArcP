"""
Generate Ultra-High-Resolution Portfolio Showcase Images for ArcP.
Composites live, pixel-accurate PyQt6 widgets (Concentric Radial HUD & Inspector Drawer)
onto an obsidian dark studio presentation canvas with ambient volumetric glows,
multi-layer drop shadows, professional typography, and feature callout annotations.
"""
from __future__ import annotations

import math
import os
import shutil
import sys
from typing import Tuple

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont
from PyQt6.QtCore import QPoint, QRect, QSize, Qt
from PyQt6.QtGui import QColor, QFont, QImage, QPainter
from PyQt6.QtWidgets import QApplication

from core.mime_router import MimeMode
from plugins.binary_ops import BinaryOpsPlugin
from ui.inspector_drawer import InspectorDrawer
from ui.radial_window import RadialWindow


def create_drop_shadow(
    source_image: Image.Image,
    offset: Tuple[int, int] = (0, 24),
    blur_radius: int = 35,
    shadow_color: Tuple[int, int, int, int] = (0, 0, 0, 160),
) -> Tuple[Image.Image, int]:
    """Generate smooth multi-layer Gaussian drop shadow for an RGBA image."""
    w, h = source_image.size
    pad = blur_radius * 2
    shadow_canvas = Image.new("RGBA", (w + pad * 2, h + pad * 2), (0, 0, 0, 0))

    # Extract alpha mask from source
    alpha = source_image.split()[3]
    # Create solid shadow mask
    solid_shadow = Image.new("RGBA", (w, h), shadow_color)
    solid_shadow.putalpha(alpha)

    # Paste shadow with offset
    shadow_canvas.paste(solid_shadow, (pad + offset[0], pad + offset[1]), solid_shadow)
    # Blur
    shadow_canvas = shadow_canvas.filter(ImageFilter.GaussianBlur(blur_radius))
    return shadow_canvas, pad


def render_qt_hud() -> Image.Image:
    """Render the 100% authentic ArcP Radial HUD at native resolution."""
    hud = RadialWindow(start_collapsed=False)
    hud.resize(520, 520)
    hud.set_active_mode(MimeMode.BINARY, manual=True)
    hud.hovered_slice_id = 3
    hud.hovered_zone = "PRIMARY"
    hud.anim_ctrl.bloom_progress = 1.0
    hud.active_bloom_slice = 3

    # Force telemetry latency
    hud.telemetry.record_latency(12.4)

    qimg = QImage(520, 520, QImage.Format.Format_ARGB32_Premultiplied)
    qimg.fill(0)
    p = QPainter(qimg)
    hud.render(p)
    p.end()

    temp_path = "temp_hud_export.png"
    qimg.save(temp_path)
    im = Image.open(temp_path).convert("RGBA")
    try:
        os.remove(temp_path)
    except Exception:
        pass
    return im


def render_qt_drawer() -> Image.Image:
    """Render the authentic ArcP Inspector Drawer with rich Python AST audit tables."""
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

    qimg = QImage(drawer.width(), drawer.height(), QImage.Format.Format_ARGB32_Premultiplied)
    qimg.fill(0)
    p = QPainter(qimg)
    drawer.render(p)
    p.end()

    temp_path = "temp_drawer_export.png"
    qimg.save(temp_path)
    im = Image.open(temp_path).convert("RGBA")
    try:
        os.remove(temp_path)
    except Exception:
        pass
    return im


def draw_ambient_glow(
    canvas: Image.Image,
    center: Tuple[int, int],
    radius: int,
    color: Tuple[int, int, int, int],
) -> None:
    """Draw soft atmospheric radial glow onto canvas."""
    glow = Image.new("RGBA", (radius * 2, radius * 2), (0, 0, 0, 0))
    d = ImageDraw.Draw(glow)
    for r in range(radius, 0, -4):
        alpha = int(color[3] * (1.0 - (r / radius) ** 1.8))
        d.ellipse(
            (radius - r, radius - r, radius + r, radius + r),
            fill=(color[0], color[1], color[2], alpha),
        )
    glow = glow.filter(ImageFilter.GaussianBlur(radius // 3))
    canvas.alpha_composite(glow, (center[0] - radius, center[1] - radius))


def get_system_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    """Get crisp Segoe UI or fallback font."""
    font_names = (
        ["segoeuib.ttf", "arialbd.ttf"] if bold else ["segoeui.ttf", "arial.ttf", "consola.ttf"]
    )
    for fn in font_names:
        try:
            return ImageFont.truetype(fn, size)
        except Exception:
            continue
    return ImageFont.load_default()


def build_portfolio_graphic(with_annotations: bool = True) -> Image.Image:
    """Build high-resolution 2880 x 1620 presentation canvas."""
    W, H = 2880, 1620
    canvas = Image.new("RGBA", (W, H), (7, 10, 16, 255))
    draw = ImageDraw.Draw(canvas)

    # 1. Background Grid Pattern (Modern Dev Matrix Grid)
    grid_size = 40
    for x in range(0, W, grid_size):
        for y in range(0, H, grid_size):
            draw.point((x, y), fill=(30, 41, 59, 110))

    # Subtle horizontal & vertical guide lines
    draw.line((0, 160, W, 160), fill=(30, 41, 59, 90), width=1)
    draw.line((0, H - 90, W, H - 90), fill=(30, 41, 59, 90), width=1)

    # 2. Ambient Volumetric Glows
    hud_center = (720, 850)
    drawer_center = (1840, 850)

    # Cyan ambient aura behind HUD
    draw_ambient_glow(canvas, hud_center, 440, (0, 245, 212, 55))
    # Indigo ambient aura behind Drawer
    draw_ambient_glow(canvas, drawer_center, 480, (99, 102, 241, 45))

    # 3. Header Typography & Branding
    font_brand = get_system_font(44, bold=True)
    font_title = get_system_font(24, bold=True)
    font_sub = get_system_font(15, bold=False)
    font_pill = get_system_font(13, bold=True)
    font_callout_title = get_system_font(15, bold=True)
    font_callout_body = get_system_font(13, bold=False)
    font_spec = get_system_font(13, bold=False)

    # Brand Title & Icon Pill
    draw.text((80, 46), "ArcP", font=font_brand, fill=(248, 250, 252, 255))
    draw.rounded_rectangle((200, 56, 320, 88), radius=6, fill=(30, 41, 59, 255), outline=(0, 245, 212, 200), width=1)
    draw.text((214, 63), "v1.1.0 • Stable", font=font_pill, fill=(0, 245, 212, 255))

    # Headline & Subtitle
    draw.text((80, 106), "Autonomous Radial Context Pipeline", font=font_title, fill=(0, 245, 212, 255))
    draw.text((560, 114), "— Zero-Disk Desktop Firewall & DevSecOps Radial Engine", font=font_sub, fill=(148, 163, 184, 255))

    # Header Technology Badges (Right-Aligned)
    badges = [
        ("PyQt6 60-FPS HUD", (0, 245, 212)),
        ("Windows Native WinRT OCR", (56, 189, 248)),
        ("Zero-Disk RAM Pipe", (129, 140, 248)),
        ("Python AST DevSecOps", (52, 211, 153)),
        ("100% Solid Matte UI", (248, 250, 252)),
    ]
    badge_x = W - 80
    for text, col in reversed(badges):
        bbox = draw.textbbox((0, 0), text, font=font_pill)
        bw = bbox[2] - bbox[0] + 24
        bx = badge_x - bw
        draw.rounded_rectangle((bx, 60, bx + bw, 94), radius=6, fill=(17, 24, 39, 230), outline=(51, 65, 85, 255), width=1)
        draw.text((bx + 12, 69), text, font=font_pill, fill=col)
        badge_x = bx - 14

    # 4. Render Live Qt Components
    hud_img = render_qt_hud()
    drawer_img = render_qt_drawer()

    # Scale HUD slightly for optimal hero balance (570x570)
    hud_scale = 570
    hud_scaled = hud_img.resize((hud_scale, hud_scale), Image.Resampling.LANCZOS)
    drawer_w, drawer_h = drawer_img.size

    # Position coordinates
    hud_pos = (hud_center[0] - hud_scale // 2, hud_center[1] - hud_scale // 2)
    drawer_pos = (drawer_center[0] - drawer_w // 2, drawer_center[1] - drawer_h // 2)

    # Multi-layer Drop Shadows
    hud_shadow, hud_pad = create_drop_shadow(hud_scaled, offset=(0, 20), blur_radius=35, shadow_color=(0, 0, 0, 180))
    drawer_shadow, drawer_pad = create_drop_shadow(drawer_img, offset=(0, 24), blur_radius=40, shadow_color=(0, 0, 0, 190))

    # Composite Shadows
    canvas.alpha_composite(hud_shadow, (hud_pos[0] - hud_pad, hud_pos[1] - hud_pad))
    canvas.alpha_composite(drawer_shadow, (drawer_pos[0] - drawer_pad, drawer_pos[1] - drawer_pad))

    # Composite App Windows
    canvas.alpha_composite(hud_scaled, hud_pos)
    canvas.alpha_composite(drawer_img, drawer_pos)

    # 5. Feature Callouts & Pointer Annotations (If requested)
    if with_annotations:
        callouts = [
            # Callout 1: Zero-Disk Gravity Well
            {
                "anchor": (hud_center[0], hud_center[1] - 80),
                "card": (100, 420, 360, 130),
                "title": "01 / ZERO-DISK IN-MEMORY STREAM",
                "body": "Direct RAM-to-clipboard streaming via io.BytesIO & QClipboard. Ephemeral TokenVault scrubs secrets with TTL expiry & Shannon entropy.",
                "color": (0, 245, 212),
            },
            # Callout 2: Polymorphic Radial Ring
            {
                "anchor": (hud_center[0] - 220, hud_center[1] + 160),
                "card": (100, 1080, 360, 130),
                "title": "02 / 60-FPS POLYMORPHIC RADIAL RING",
                "body": "7 adaptive context modes with 28 specialized micro-actions. Instant <10ms MIME sniffing, scroll wheel cycling & sticky manual mode lock.",
                "color": (99, 102, 241),
            },
            # Callout 3: Inspector Drawer
            {
                "anchor": (drawer_pos[0] + 320, drawer_pos[1] + 20),
                "card": (W - 460, 420, 360, 130),
                "title": "03 / SOLID MATTE INSPECTOR DRAWER",
                "body": "Frameless hardware-accelerated diagnostic viewport with dark-mode Markdown tables, code syntax highlighting & one-click clipboard copying.",
                "color": (56, 189, 248),
            },
            # Callout 4: AST DevSecOps Audit
            {
                "anchor": (drawer_pos[0] + 520, drawer_pos[1] + drawer_h - 120),
                "card": (W - 460, 1080, 360, 130),
                "title": "04 / PURE-PYTHON AST & THREAT INTEL",
                "body": "Extracts classes, methods, imports, type-annotated constants (ast.AnnAssign), ELF/PE headers, and threat-intel IOCs from dropped payloads.",
                "color": (52, 211, 153),
            },
        ]

        for c in callouts:
            cx, cy, cw, ch = c["card"]
            ax, ay = c["anchor"]
            col = c["color"]

            # Draw Card Container
            draw.rounded_rectangle((cx, cy, cx + cw, cy + ch), radius=8, fill=(15, 23, 42, 235), outline=(51, 65, 85, 255), width=1)
            # Accent Top Line on Card
            draw.line((cx + 10, cy, cx + 60, cy), fill=col, width=2)

            # Draw Title & Body
            draw.text((cx + 16, cy + 14), c["title"], font=font_callout_title, fill=col)

            # Word wrap body text
            words = c["body"].split()
            lines = []
            cur_line = []
            for w_text in words:
                cur_line.append(w_text)
                bbox = draw.textbbox((0, 0), " ".join(cur_line), font=font_callout_body)
                if bbox[2] - bbox[0] > cw - 32:
                    cur_line.pop()
                    lines.append(" ".join(cur_line))
                    cur_line = [w_text]
            if cur_line:
                lines.append(" ".join(cur_line))

            for idx, line in enumerate(lines[:4]):
                draw.text((cx + 16, cy + 42 + idx * 20), line, font=font_callout_body, fill=(226, 232, 240, 240))

            # Draw Sleek Connecting Hairline Pointer
            if cx < ax:
                start_pt = (cx + cw, cy + ch // 2)
            else:
                start_pt = (cx, cy + ch // 2)

            mid_x = (start_pt[0] + ax) // 2
            draw.line([start_pt, (mid_x, start_pt[1]), (mid_x, ay), (ax, ay)], fill=(col[0], col[1], col[2], 140), width=1)
            # Small circle anchor
            draw.ellipse((ax - 4, ay - 4, ax + 4, ay + 4), fill=(0, 0, 0, 255), outline=col, width=2)

    # 6. Footer System Specifications Bar
    draw.rounded_rectangle((80, H - 72, W - 80, H - 24), radius=8, fill=(15, 23, 42, 240), outline=(30, 41, 59, 255), width=1)

    specs = [
        "ARCHITECTURE: PyQt6 + QPainter 2D Hardware-Accelerated",
        "SECURITY: Reversible TokenVault & Shannon Entropy PII Scrubbing",
        "AI / CV: Windows Native WinRT Neural OCR & Targeted Redactor",
        "STORAGE: Zero-Disk Ephemeral Footprint (RAM Only)",
        "GITHUB: rahulchandra2004/ArcP",
    ]

    spec_spacing = (W - 200) // len(specs)
    for i, s in enumerate(specs):
        sx = 110 + i * spec_spacing
        draw.text((sx, H - 54), s, font=font_spec, fill=(148, 163, 184, 255))
        if i < len(specs) - 1:
            draw.text((sx + spec_spacing - 24, H - 54), "•", font=font_spec, fill=(51, 65, 85, 255))

    return canvas


def main() -> None:
    app = QApplication([])
    print("Generating ultra-high-resolution portfolio showcase graphics...")

    out_annotated = "arcp_portfolio_showcase.png"
    out_clean = "arcp_portfolio_clean.png"

    # 1. Annotated Showcase Hero
    canvas_annotated = build_portfolio_graphic(with_annotations=True)
    canvas_annotated.save(out_annotated, quality=95, optimize=True)
    print(f"Saved: {out_annotated} ({canvas_annotated.size[0]}x{canvas_annotated.size[1]})")

    # 2. Clean Minimalist Showcase Hero
    canvas_clean = build_portfolio_graphic(with_annotations=False)
    canvas_clean.save(out_clean, quality=95, optimize=True)
    print(f"Saved: {out_clean} ({canvas_clean.size[0]}x{canvas_clean.size[1]})")

    # Copy to artifacts directory so it can be previewed/embedded
    artifact_dir = r"C:\Users\Rahul\.gemini\antigravity\brain\b91e6ad2-6800-42bb-b098-fe73727c9d91"
    if os.path.exists(artifact_dir):
        dest_annotated = os.path.join(artifact_dir, "arcp_portfolio_showcase.png")
        dest_clean = os.path.join(artifact_dir, "arcp_portfolio_clean.png")
        shutil.copy2(out_annotated, dest_annotated)
        shutil.copy2(out_clean, dest_clean)
        print(f"Copied assets to artifact directory: {artifact_dir}")


if __name__ == "__main__":
    main()
