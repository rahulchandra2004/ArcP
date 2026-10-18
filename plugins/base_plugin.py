"""
Base Plugin Interface and Execution Strategy for ArcP Radial Actions.
All polymorphic mode handlers inherit from RadialAction.
"""
from __future__ import annotations

import io
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from core.mime_router import MimeMode


@dataclass
class SubSliceConfig:
    """Definition for a concentric sub-slice."""
    id: str
    name: str
    description: str


@dataclass
class SliceConfig:
    """Definition for a primary radial slice."""
    slice_id: int  # 1: Top, 2: Right, 3: Bottom, 4: Left
    name: str
    description: str
    sub_slices: List[SubSliceConfig] = field(default_factory=list)


@dataclass
class PipeResult:
    """Unified container for all plugin outputs streamed to memory/clipboard."""
    data: Any
    action_name: str
    mode: MimeMode
    latency_ms: float = 0.0
    secrets_blocked: int = 0
    bytes_streamed: int = 0
    is_html: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


class RadialAction(ABC):
    """
    Abstract Strategy pattern interface for polymorphic ArcP plugins.
    Each plugin manages one MimeMode and provides 4 primary slices + sub-slices.
    """

    def __init__(self, mode: MimeMode, name: str) -> None:
        self.mode = mode
        self.name = name
        self.slices: Dict[int, SliceConfig] = {}

    @abstractmethod
    def execute(
        self,
        payload: Any,
        slice_id: int,
        sub_option: Optional[str] = None,
    ) -> PipeResult:
        """
        Execute the radial action in RAM and return a PipeResult.
        Must never create temporary files on disk.
        """
        raise NotImplementedError

    @staticmethod
    def read_payload_bytes(payload: Any) -> bytes:
        """Extract raw bytes from string path, bytes, or file-like object."""
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, bytearray):
            return bytes(payload)
        if isinstance(payload, str):
            if os.path.exists(payload) and os.path.isfile(payload):
                with open(payload, "rb") as f:
                    return f.read()
            return payload.encode("utf-8")
        if hasattr(payload, "read"):
            return payload.read()
        return str(payload).encode("utf-8")

    @staticmethod
    def read_payload_text(payload: Any) -> str:
        """Extract UTF-8 text from payload."""
        if isinstance(payload, str):
            if os.path.exists(payload) and os.path.isfile(payload):
                with open(payload, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            return payload
        if isinstance(payload, (bytes, bytearray)):
            return payload.decode("utf-8", errors="replace")
        return str(payload)
