"""
Polar Collision Geometry and QPainterPath Arc Mathematics for ArcP.
Converts Cartesian screen coordinates to polar (r, theta) and builds anti-aliased donut sectors.
"""
from __future__ import annotations

import math
from typing import Dict, Optional, Tuple

from PyQt6.QtCore import QPointF, QRectF
from PyQt6.QtGui import QPainterPath


# Radial concentric ring boundaries (in pixels)
R_GRAVITY_WELL = 65.0
R_PRIMARY_INNER = 65.0
R_PRIMARY_OUTER = 175.0
R_CONCENTRIC_INNER = 180.0
R_CONCENTRIC_OUTER = 245.0

# Slice angular parameters (degrees)
SECTOR_SPAN = 90.0
GAP_SPAN = 4.0
ACTIVE_SPAN = SECTOR_SPAN - GAP_SPAN  # 86 degrees

# Primary slice nominal angular centers & bounds
# Slice 1: Top (centered at 270 deg)
# Slice 2: Right (centered at 0 deg)
# Slice 3: Bottom (centered at 90 deg)
# Slice 4: Left (centered at 180 deg)
SLICE_ANGLES = {
    1: {"center": 270.0, "start": 225.0 + GAP_SPAN / 2, "sweep": ACTIVE_SPAN},
    2: {"center": 0.0, "start": (315.0 + GAP_SPAN / 2) % 360.0, "sweep": ACTIVE_SPAN},
    3: {"center": 90.0, "start": 45.0 + GAP_SPAN / 2, "sweep": ACTIVE_SPAN},
    4: {"center": 180.0, "start": 135.0 + GAP_SPAN / 2, "sweep": ACTIVE_SPAN},
}


def cartesian_to_polar(x: float, y: float, xc: float, yc: float) -> Tuple[float, float]:
    """
    Convert Cartesian coordinates (x, y) relative to center (xc, yc) into (r, theta).
    Radius: r = sqrt((x - xc)^2 + (y - yc)^2)
    Angle: theta = (degrees(atan2(y - yc, x - xc)) + 360) % 360
    """
    dx = x - xc
    dy = y - yc
    r = math.hypot(dx, dy)
    theta = (math.degrees(math.atan2(dy, dx)) + 360.0) % 360.0
    return r, theta


def polar_to_cartesian(r: float, theta_deg: float, xc: float, yc: float) -> Tuple[float, float]:
    """Convert polar coordinates (r, theta) into Cartesian (x, y)."""
    rad = math.radians(theta_deg)
    x = xc + r * math.cos(rad)
    y = yc + r * math.sin(rad)
    return x, y


def build_donut_sector_path(
    xc: float,
    yc: float,
    r_in: float,
    r_out: float,
    start_deg: float,
    sweep_deg: float,
) -> QPainterPath:
    """
    Build a crisp anti-aliased donut sector QPainterPath.
    Uses arcMoveTo, arcTo, and closeSubpath.
    Qt 0 deg is right, 90 deg is top (counter-clockwise).
    Screen angle 0 deg is right, 90 deg is bottom (clockwise).
    """
    path = QPainterPath()
    rect_out = QRectF(xc - r_out, yc - r_out, r_out * 2.0, r_out * 2.0)
    rect_in = QRectF(xc - r_in, yc - r_in, r_in * 2.0, r_in * 2.0)

    # Convert screen clockwise angle to Qt counter-clockwise angle
    qt_start = (360.0 - start_deg) % 360.0
    qt_sweep = -sweep_deg

    path.arcMoveTo(rect_out, qt_start)
    path.arcTo(rect_out, qt_start, qt_sweep)
    path.arcTo(rect_in, qt_start + qt_sweep, -qt_sweep)
    path.closeSubpath()
    return path


def angle_in_sector(theta: float, center_deg: float) -> bool:
    """Check if theta is within +- 45 deg of center_deg."""
    diff = (theta - center_deg + 180.0) % 360.0 - 180.0
    return abs(diff) <= (SECTOR_SPAN / 2.0)


def angle_offset_in_sector(theta: float, start_deg: float) -> float:
    """Compute angular offset from sector start [0, 360)."""
    return (theta - start_deg + 360.0) % 360.0


def resolve_radial_collision(
    x: float,
    y: float,
    xc: float,
    yc: float,
    sub_slice_counts: Optional[Dict[int, int]] = None,
) -> Tuple[Optional[int], Optional[int], str]:
    """
    Map Cartesian drop/hover point to radial collision target.
    Returns: (slice_id, sub_slice_idx, zone_name)
    Zones:
      - 'GRAVITY_WELL' (slice_id = 0, sub_slice_idx = None)
      - 'PRIMARY' (slice_id = 1..4, sub_slice_idx = None)
      - 'CONCENTRIC' (slice_id = 1..4, sub_slice_idx = 0..N-1)
      - 'VOID' (None, None, 'VOID')
    """
    r, theta = cartesian_to_polar(x, y, xc, yc)

    # 1. Center Gravity Well
    if r < R_GRAVITY_WELL:
        return 0, None, "GRAVITY_WELL"

    # Identify primary sector (1: Top, 2: Right, 3: Bottom, 4: Left)
    parent_slice_id: Optional[int] = None
    if angle_in_sector(theta, 270.0):
        parent_slice_id = 1
    elif angle_in_sector(theta, 0.0):
        parent_slice_id = 2
    elif angle_in_sector(theta, 90.0):
        parent_slice_id = 3
    elif angle_in_sector(theta, 180.0):
        parent_slice_id = 4

    if parent_slice_id is None:
        return None, None, "VOID"

    cfg = SLICE_ANGLES[parent_slice_id]
    offset = angle_offset_in_sector(theta, cfg["start"])

    # Check if point falls in angular gap between sectors
    in_active_arc = offset <= cfg["sweep"]

    # 2. Inner Primary Ring
    if R_PRIMARY_INNER <= r <= R_PRIMARY_OUTER:
        if in_active_arc:
            return parent_slice_id, None, "PRIMARY"
        return None, None, "VOID"

    # 3. Outer Concentric Ring
    if R_CONCENTRIC_INNER <= r <= R_CONCENTRIC_OUTER:
        if in_active_arc:
            counts = sub_slice_counts or {}
            num_subs = counts.get(parent_slice_id, 0)
            if num_subs > 0:
                sub_span = cfg["sweep"] / num_subs
                sub_idx = min(num_subs - 1, int(offset / sub_span))
                return parent_slice_id, sub_idx, "CONCENTRIC"
            return parent_slice_id, None, "PRIMARY"
        return None, None, "VOID"

    return None, None, "VOID"
