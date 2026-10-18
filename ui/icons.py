"""
ArcP High-Definition Cyber Icon Engine & Asset Registry.
Provides zero-disk in-memory caching of high-resolution cyber icons,
SVG rendering, QPixmap scaling, and ASCII-safe tags for Windows cp1252 consoles.
"""
from __future__ import annotations

import base64
import os
from typing import Dict, Optional

from PyQt6.QtCore import QByteArray, QRectF, QSize, Qt
from PyQt6.QtGui import QColor, QIcon, QImage, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer

# Embedded fallback SVGs ensuring 100% in-memory zero-disk operation
# Modern hollow duotone stroke vector designs (stroke-width: 2.2, round caps & joins)
EMBEDDED_SVGS: Dict[str, str] = {
    "diff": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="3" width="18" height="18" rx="2"/>
  <line x1="12" y1="3" x2="12" y2="21"/>
  <line x1="6" y1="8" x2="9" y2="8"/>
  <line x1="7.5" y1="6.5" x2="7.5" y2="9.5"/>
  <line x1="15" y1="8" x2="18" y2="8"/>
</svg>""",

    "commit": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="4"/>
  <line x1="2" y1="12" x2="8" y2="12"/>
  <line x1="16" y1="12" x2="22" y2="12"/>
</svg>""",

    "git_branch": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <line x1="6" y1="3" x2="6" y2="15"/>
  <circle cx="18" cy="6" r="3"/>
  <circle cx="6" cy="18" r="3"/>
  <path d="M18 9a9 9 0 0 1-9 9"/>
</svg>""",

    "lock": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="4" y="11" width="16" height="10" rx="2" ry="2"/>
  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  <circle cx="12" cy="16" r="1.2"/>
</svg>""",

    "cpu": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="4" y="4" width="16" height="16" rx="2"/>
  <rect x="9" y="9" width="6" height="6"/>
  <path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>
</svg>""",

    "layers": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <polygon points="12 2 2 7 12 12 22 7 12 2"/>
  <polyline points="2 17 12 22 22 17"/>
  <polyline points="2 12 12 17 22 12"/>
</svg>""",

    "binary": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="4" width="7" height="16" rx="2"/>
  <line x1="17" y1="4" x2="17" y2="20"/>
  <line x1="14.5" y1="7" x2="17" y2="4"/>
  <line x1="14" y1="20" x2="20" y2="20"/>
</svg>""",

    "container": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/>
  <path d="m3.3 7 8.7 5 8.7-5"/>
  <path d="M12 22V12"/>
</svg>""",

    "terminal": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <polyline points="4 17 10 11 4 5"/>
  <line x1="12" y1="19" x2="20" y2="19"/>
</svg>""",

    "shield": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
</svg>""",

    "search": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="11" cy="11" r="7"/>
  <line x1="21" y1="21" x2="16.65" y2="16.65"/>
</svg>""",

    "zap": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
</svg>""",

    "sparkle": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M12 2l2.4 5.6L20 10l-5.6 2.4L12 18l-2.4-5.6L4 10l5.6-2.4z"/>
  <circle cx="19" cy="5" r="1.2"/>
  <circle cx="5" cy="19" r="1.2"/>
</svg>""",

    "microscope": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M6 18h8M3 22h18M14 22a7 7 0 1 0-7-7h1"/>
  <circle cx="9" cy="9" r="2"/>
  <path d="m14 8 3-3 4 4-3 3M12 10l5 5"/>
</svg>""",

    "database": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <ellipse cx="12" cy="5" rx="9" ry="3"/>
  <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
</svg>""",

    "hash": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <line x1="4" y1="9" x2="20" y2="9"/>
  <line x1="4" y1="15" x2="20" y2="15"/>
  <line x1="10" y1="3" x2="8" y2="21"/>
  <line x1="16" y1="3" x2="14" y2="21"/>
</svg>""",

    "package": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <path d="m7.5 4.27 9 5.15M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/>
  <path d="m3.3 7 8.7 5 8.7-5M12 22V12"/>
</svg>""",

    "check": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="10"/>
  <path d="m9 12 2 2 4-4"/>
</svg>""",

    "cross": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="10"/>
  <line x1="15" y1="9" x2="9" y2="15"/>
  <line x1="9" y1="9" x2="15" y2="15"/>
</svg>""",

    "alert": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
  <line x1="12" y1="9" x2="12" y2="13"/>
  <line x1="12" y1="17" x2="12.01" y2="17"/>
</svg>""",

    "arcp_logo": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="9"/>
  <circle cx="12" cy="12" r="4.5"/>
  <circle cx="12" cy="12" r="1"/>
  <line x1="12" y1="1" x2="12" y2="3"/>
  <line x1="12" y1="21" x2="12" y2="23"/>
  <line x1="1" y1="12" x2="3" y2="12"/>
  <line x1="21" y1="12" x2="23" y2="12"/>
</svg>""",
}

# ASCII-safe console tags for Windows cp1252 compatibility
ASCII_TAGS: Dict[str, str] = {
    "diff": "[DIFF]",
    "commit": "[COMMIT]",
    "git_branch": "[BRANCH]",
    "lock": "[VAULT]",
    "cpu": "[CPU]",
    "layers": "[LAYERS]",
    "binary": "[BIN]",
    "container": "[CONTAINER]",
    "terminal": "[TERM]",
    "shield": "[SECURE]",
    "search": "[SEARCH]",
    "zap": "[ZAP]",
    "sparkle": "[SPARKLE]",
    "microscope": "[XRAY]",
    "database": "[DATA]",
    "hash": "[HASH]",
    "package": "[QUEUE]",
    "check": "[OK]",
    "cross": "[BLOCK]",
    "alert": "[ALERT]",
    "arcp_logo": "[ARCP]",
}


class IconRegistry:
    """Zero-disk in-memory cache for high-definition cyber vector icons with 64x64 Retina supersampling."""

    _pixmap_cache: Dict[str, QPixmap] = {}
    _icon_cache: Dict[str, QIcon] = {}

    @classmethod
    def get_svg(cls, name: str) -> str:
        """Retrieve SVG source, checking assets/icons/ then embedded RAM definitions."""
        norm_name = name.lower().replace(".svg", "").replace(".png", "")

        # Try disk file if assets/icons exists
        disk_path = os.path.join("assets", "icons", f"{norm_name}.svg")
        if os.path.exists(disk_path):
            try:
                with open(disk_path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception:
                pass

        return EMBEDDED_SVGS.get(norm_name, EMBEDDED_SVGS["arcp_logo"])

    @classmethod
    def get_pixmap(cls, name: str, size: int = 24) -> QPixmap:
        """Render and cache crisp high-DPI QPixmap at specified dimension."""
        cache_key = f"{name}_{size}"
        if cache_key in cls._pixmap_cache:
            return cls._pixmap_cache[cache_key]

        svg_content = cls.get_svg(name)
        renderer = QSvgRenderer(QByteArray(svg_content.encode("utf-8")))

        image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
        image.fill(Qt.GlobalColor.transparent)

        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
        renderer.render(painter, QRectF(0, 0, size, size))
        painter.end()

        pix = QPixmap.fromImage(image)
        cls._pixmap_cache[cache_key] = pix
        return pix

    @classmethod
    def get_tinted_pixmap(cls, name: str, size: int = 20, color: Optional[QColor] = None) -> QPixmap:
        """Render and cache a razor-sharp high-DPI vector icon supersampled from a 64x64 physical buffer."""
        color_tag = color.name() if color else "orig"
        cache_key = f"{name}_{size}_{color_tag}"
        if cache_key in cls._pixmap_cache:
            return cls._pixmap_cache[cache_key]

        svg_content = cls.get_svg(name)
        renderer = QSvgRenderer(QByteArray(svg_content.encode("utf-8")))

        buffer_size = 64
        image = QImage(buffer_size, buffer_size, QImage.Format.Format_ARGB32_Premultiplied)
        image.fill(Qt.GlobalColor.transparent)

        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
        margin = 4.0
        renderer.render(painter, QRectF(margin, margin, buffer_size - 2 * margin, buffer_size - 2 * margin))
        painter.end()

        if color is not None:
            painter_tint = QPainter(image)
            painter_tint.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
            painter_tint.fillRect(image.rect(), color)
            painter_tint.end()

        image.setDevicePixelRatio(buffer_size / float(size))
        tinted_pix = QPixmap.fromImage(image)
        cls._pixmap_cache[cache_key] = tinted_pix
        return tinted_pix

    @classmethod
    def get_icon(cls, name: str) -> QIcon:
        """Create and cache multi-resolution QIcon."""
        if name in cls._icon_cache:
            return cls._icon_cache[name]

        icon = QIcon()
        for s in (16, 24, 32, 48, 64, 128):
            icon.addPixmap(cls.get_pixmap(name, size=s))

        cls._icon_cache[name] = icon
        return icon

    @classmethod
    def get_data_uri(cls, name: str) -> str:
        """Generate base64 data URI for embedding into HTML documents."""
        svg_content = cls.get_svg(name)
        b64 = base64.b64encode(svg_content.encode("utf-8")).decode("ascii")
        return f"data:image/svg+xml;base64,{b64}"

    @classmethod
    def get_ascii_tag(cls, name: str) -> str:
        """Return safe ASCII bracketed tag for console outputs."""
        norm_name = name.lower().replace(".svg", "").replace(".png", "")
        return ASCII_TAGS.get(norm_name, "[ARCP]")
