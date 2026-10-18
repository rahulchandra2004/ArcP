"""
ArcP Asset Generator: High-Definition Cyberpunk Emojis & Icons
Generates both scalable SVGs and crisp 128x128 PNGs into assets/icons/
"""
from __future__ import annotations

import os
import sys
from PyQt6.QtCore import QByteArray, QSize, Qt
from PyQt6.QtGui import QColor, QImage, QPainter
from PyQt6.QtSvg import QSvgRenderer

ICONS_SVG = {
    "zap.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="zapGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00F5D4"/>
      <stop offset="100%" stop-color="#00BBF9"/>
    </linearGradient>
  </defs>
  <polygon points="36,4 12,34 30,34 22,60 52,28 34,28" fill="#00F5D4" opacity="0.35"/>
  <polygon points="36,6 16,33 32,33 25,56 48,30 32,30" fill="url(#zapGrad)" stroke="#E0FBFC" stroke-width="1.8" stroke-linejoin="round"/>
  <polygon points="34,12 22,31 32,31 28,46 41,31 31,31" fill="#FFFFFF" opacity="0.85"/>
</svg>""",

    "package.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="boxTop" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1E293B"/>
      <stop offset="100%" stop-color="#0F172A"/>
    </linearGradient>
    <linearGradient id="boxLeft" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0F172A"/>
      <stop offset="100%" stop-color="#090D16"/>
    </linearGradient>
    <linearGradient id="boxRight" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#172554"/>
      <stop offset="100%" stop-color="#0F172A"/>
    </linearGradient>
  </defs>
  <polygon points="32,8 54,20 32,32 10,20" fill="url(#boxTop)" stroke="#00F5D4" stroke-width="2" stroke-linejoin="round"/>
  <polygon points="10,20 32,32 32,56 10,44" fill="url(#boxLeft)" stroke="#00F5D4" stroke-width="2" stroke-linejoin="round"/>
  <polygon points="32,32 54,20 54,44 32,56" fill="url(#boxRight)" stroke="#00F5D4" stroke-width="2" stroke-linejoin="round"/>
  <polygon points="32,8 37,11 26,17 21,14" fill="#00F5D4" opacity="0.85"/>
  <polygon points="21,14 26,17 26,47 21,44" fill="#00F5D4" opacity="0.65"/>
  <circle cx="32" cy="32" r="3.5" fill="#6366F1" stroke="#00F5D4" stroke-width="1.5"/>
</svg>""",

    "shield.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#6366F1"/>
      <stop offset="50%" stop-color="#0F172A"/>
      <stop offset="100%" stop-color="#00F5D4"/>
    </linearGradient>
  </defs>
  <path d="M32,6 L54,14 C54,36 44,52 32,58 C20,52 10,36 10,14 Z" fill="url(#shieldGrad)" stroke="#00F5D4" stroke-width="2.5" stroke-linejoin="round"/>
  <path d="M32,14 L46,20 C46,34 38,45 32,49 C26,45 18,34 18,20 Z" fill="#0B0F19" stroke="#6366F1" stroke-width="1.5"/>
  <path d="M32,23 L32,33 M27,28 L37,28" stroke="#00F5D4" stroke-width="2.5" stroke-linecap="round"/>
  <circle cx="32" cy="40" r="2.5" fill="#00F5D4"/>
</svg>""",

    "alert.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="alertGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#F59E0B"/>
      <stop offset="100%" stop-color="#EF4444"/>
    </linearGradient>
  </defs>
  <polygon points="32,8 58,52 6,52" fill="#1E1B18" stroke="url(#alertGrad)" stroke-width="3" stroke-linejoin="round"/>
  <polygon points="32,16 50,48 14,48" fill="#F59E0B" opacity="0.2"/>
  <rect x="29.5" y="24" width="5" height="15" rx="2.5" fill="#F59E0B"/>
  <circle cx="32" cy="44" r="3" fill="#F59E0B"/>
</svg>""",

    "check.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="checkGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#10B981"/>
      <stop offset="100%" stop-color="#00F5D4"/>
    </linearGradient>
  </defs>
  <polygon points="32,6 54,18 54,46 32,58 10,46 10,18" fill="#091E1A" stroke="url(#checkGrad)" stroke-width="2.5" stroke-linejoin="round"/>
  <path d="M20,32 L28,40 L44,22" fill="none" stroke="#00F5D4" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>""",

    "cross.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="crossGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#EF4444"/>
      <stop offset="100%" stop-color="#F43F5E"/>
    </linearGradient>
  </defs>
  <polygon points="20,6 44,6 58,20 58,44 44,58 20,58 6,44 6,20" fill="#200B10" stroke="url(#crossGrad)" stroke-width="2.5" stroke-linejoin="round"/>
  <line x1="22" y1="22" x2="42" y2="42" stroke="#EF4444" stroke-width="4.5" stroke-linecap="round"/>
  <line x1="42" y1="22" x2="22" y2="42" stroke="#EF4444" stroke-width="4.5" stroke-linecap="round"/>
</svg>""",

    "search.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="lensGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00F5D4"/>
      <stop offset="100%" stop-color="#6366F1"/>
    </linearGradient>
  </defs>
  <circle cx="28" cy="28" r="18" fill="#0B132B" stroke="url(#lensGrad)" stroke-width="3"/>
  <circle cx="28" cy="28" r="10" fill="none" stroke="#00F5D4" stroke-width="1.2" stroke-dasharray="2,2"/>
  <line x1="28" y1="14" x2="28" y2="42" stroke="#00F5D4" stroke-width="1" opacity="0.6"/>
  <line x1="14" y1="28" x2="42" y2="28" stroke="#00F5D4" stroke-width="1" opacity="0.6"/>
  <line x1="41" y1="41" x2="56" y2="56" stroke="#6366F1" stroke-width="4.5" stroke-linecap="round"/>
  <circle cx="56" cy="56" r="2.5" fill="#00F5D4"/>
</svg>""",

    "microscope.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="scopeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#A855F7"/>
      <stop offset="100%" stop-color="#00F5D4"/>
    </linearGradient>
  </defs>
  <rect x="26" y="10" width="12" height="24" rx="3" fill="#0F172A" stroke="url(#scopeGrad)" stroke-width="2"/>
  <circle cx="32" cy="16" r="3" fill="#00F5D4"/>
  <rect x="36" y="22" width="6" height="4" rx="1" fill="#6366F1"/>
  <polygon points="28,34 36,34 34,42 30,42" fill="#00F5D4"/>
  <line x1="16" y1="46" x2="48" y2="46" stroke="#00F5D4" stroke-width="2"/>
  <line x1="32" y1="42" x2="32" y2="46" stroke="#A855F7" stroke-width="3" stroke-linecap="round"/>
  <path d="M22,46 L22,54 L42,54 L42,46" fill="none" stroke="#6366F1" stroke-width="2.5"/>
</svg>""",

    "lock.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="lockGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#6366F1"/>
      <stop offset="100%" stop-color="#00F5D4"/>
    </linearGradient>
  </defs>
  <path d="M22,28 L22,18 C22,12 26,8 32,8 C38,8 42,12 42,18 L42,28" fill="none" stroke="#00F5D4" stroke-width="3.5" stroke-linecap="round"/>
  <rect x="16" y="26" width="32" height="28" rx="6" fill="#0F172A" stroke="url(#lockGrad)" stroke-width="2.5"/>
  <circle cx="32" cy="38" r="3.5" fill="#00F5D4"/>
  <polygon points="30,39 34,39 33,47 31,47" fill="#00F5D4"/>
</svg>""",

    "sparkle.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="sparkGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#FFFFFF"/>
      <stop offset="50%" stop-color="#00F5D4"/>
      <stop offset="100%" stop-color="#6366F1"/>
    </linearGradient>
  </defs>
  <path d="M32,4 Q32,32 60,32 Q32,32 32,60 Q32,32 4,32 Q32,32 32,4 Z" fill="url(#sparkGrad)"/>
  <circle cx="16" cy="16" r="2" fill="#00F5D4"/>
  <circle cx="48" cy="16" r="2" fill="#00F5D4"/>
  <circle cx="16" cy="48" r="2" fill="#00F5D4"/>
  <circle cx="48" cy="48" r="2" fill="#00F5D4"/>
</svg>""",

    "arcp_logo.svg": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00F5D4"/>
      <stop offset="100%" stop-color="#6366F1"/>
    </linearGradient>
  </defs>
  <circle cx="32" cy="32" r="27" fill="#0B0F19" stroke="url(#logoGrad)" stroke-width="3"/>
  <circle cx="32" cy="32" r="18" fill="none" stroke="#00F5D4" stroke-width="1.8" stroke-dasharray="6,4"/>
  <circle cx="32" cy="32" r="8" fill="#00F5D4"/>
  <line x1="32" y1="2" x2="32" y2="8" stroke="#00F5D4" stroke-width="2"/>
  <line x1="32" y1="56" x2="32" y2="62" stroke="#00F5D4" stroke-width="2"/>
  <line x1="2" y1="32" x2="8" y2="32" stroke="#00F5D4" stroke-width="2"/>
  <line x1="56" y1="32" x2="62" y2="32" stroke="#00F5D4" stroke-width="2"/>
</svg>"""
}


def generate_all(out_dir: str = "assets/icons") -> None:
    os.makedirs(out_dir, exist_ok=True)
    size = 128

    for filename, svg_str in ICONS_SVG.items():
        base_name = os.path.splitext(filename)[0]
        svg_path = os.path.join(out_dir, filename)
        png_path = os.path.join(out_dir, f"{base_name}.png")

        # 1. Save SVG
        with open(svg_path, "w", encoding="utf-8") as f:
            f.write(svg_str)

        # 2. Render 128x128 High-DPI PNG
        renderer = QSvgRenderer(QByteArray(svg_str.encode("utf-8")))
        image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
        image.fill(Qt.GlobalColor.transparent)

        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
        renderer.render(painter)
        painter.end()

        image.save(png_path, "PNG")
        print(f"[ArcP Asset] Generated {svg_path} & {png_path}")


if __name__ == "__main__":
    generate_all()
