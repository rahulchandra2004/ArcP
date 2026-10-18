"""
Polymorphic MIME Router for ArcP.
Performs sub-10ms classification using header magic bytes, extension matching, and content heuristics.
"""
from __future__ import annotations

import os
import struct
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Tuple, Union

try:
    from PyQt6.QtCore import QMimeData
except ImportError:
    QMimeData = None  # type: ignore


class MimeMode(str, Enum):
    """The 7 Polymorphic Operational Modes of ArcP."""
    IMAGE = "IMAGE"
    DATASET = "DATASET"
    CODE_LOG = "CODE_LOG"
    ML_MODEL = "ML_MODEL"
    INFRA = "INFRA"
    BINARY = "BINARY"
    GIT_PATCH = "GIT_PATCH"


class MimeRouter:
    """High-speed header and extension classifier (<10ms latency)."""

    # Magic byte signatures
    _MAGIC_PNG = b"\x89PNG\r\n\x1a\n"
    _MAGIC_JPEG = b"\xff\xd8\xff"
    _MAGIC_BMP = b"BM"
    _MAGIC_RIFF = b"RIFF"
    _MAGIC_WEBP = b"WEBP"
    _MAGIC_PARQUET = b"PAR1"
    _MAGIC_SQLITE = b"SQLite format 3\x00"
    _MAGIC_ELF = b"\x7fELF"
    _MAGIC_MZ = b"MZ"
    _MAGIC_HDF5 = b"\x89HDF\r\n\x1a\n"
    _MAGIC_ZIP = b"PK\x03\x04"
    _MAGIC_MACHO_32 = b"\xfe\xed\xfa\xce"
    _MAGIC_MACHO_64 = b"\xfe\xed\xfa\xcf"
    _MAGIC_MACHO_FAT = b"\xca\xfe\xba\xbe"

    # Known extensions
    _IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tiff", ".tif", ".ico"}
    _DATASET_EXTS = {".csv", ".tsv", ".parquet", ".pq", ".sqlite", ".sqlite3", ".db"}
    _ML_EXTS = {".pt", ".pth", ".onnx", ".safetensors", ".pkl", ".pickle", ".h5", ".keras", ".tflite"}
    _BINARY_EXTS = {".exe", ".dll", ".so", ".elf", ".bin", ".o", ".dylib", ".sys", ".class"}
    _GIT_EXTS = {".diff", ".patch"}
    _INFRA_NAMES = {"dockerfile", "containerfile", "docker-compose.yml", "docker-compose.yaml"}
    _INFRA_EXTS = {".tf", ".tfvars", ".k8s"}
    _CODE_LOG_EXTS = {
        ".log", ".txt", ".py", ".js", ".ts", ".jsx", ".tsx", ".cpp", ".c", ".h",
        ".hpp", ".rs", ".go", ".java", ".sh", ".bash", ".zsh", ".bat", ".ps1",
        ".env", ".md", ".rst", ".toml", ".ini", ".cfg", ".xml", ".html", ".css",
    }

    @classmethod
    def classify_payload(
        cls,
        payload: Union[str, bytes, Path, Any],
        hint_filename: Optional[str] = None
    ) -> Tuple[MimeMode, str]:
        """
        Classifies an arbitrary payload (path, raw bytes, string, or QMimeData).
        Returns: (MimeMode, description_string)
        """
        # 1. QMimeData inspection
        if QMimeData is not None and isinstance(payload, QMimeData):
            return cls._classify_mime_data(payload)

        # 2. Local File or Directory Path
        if isinstance(payload, (str, Path)):
            path_str = str(payload).strip()
            if os.path.exists(path_str):
                path_obj = Path(path_str)
                # Check for git repository directory
                if path_obj.is_dir():
                    if (path_obj / ".git").exists() or path_obj.name == ".git":
                        return MimeMode.GIT_PATCH, f"Git Repository: {path_obj.name}"
                    return MimeMode.INFRA, f"Directory: {path_obj.name}"

                # Read first 256 header bytes
                header = b""
                try:
                    with open(path_str, "rb") as f:
                        header = f.read(256)
                except Exception:
                    header = b""

                return cls._classify_from_header_and_name(header, path_obj.name)

            # Not an existing path, treat as raw string/text
            return cls._classify_text_content(path_str, hint_filename)

        # 3. Raw Bytes
        if isinstance(payload, (bytes, bytearray, memoryview)):
            raw_bytes = bytes(payload[:256])
            return cls._classify_from_header_and_name(raw_bytes, hint_filename or "buffer.bin")

        return MimeMode.CODE_LOG, "Generic Text / Unclassified"

    @classmethod
    def _classify_mime_data(cls, mime: QMimeData) -> Tuple[MimeMode, str]:
        """Inspect PyQt6 QMimeData in <10ms."""
        # Clipboard or Dragged Image
        if mime.hasImage():
            return MimeMode.IMAGE, "In-Memory Image Object"

        # URLs / File drops
        if mime.hasUrls():
            urls = mime.urls()
            if urls:
                first_url = urls[0]
                if first_url.isLocalFile():
                    local_path = first_url.toLocalFile()
                    return cls.classify_payload(local_path)
                return MimeMode.CODE_LOG, f"Remote URL: {first_url.toString()}"

        # Text stream
        if mime.hasText():
            text = mime.text()
            return cls._classify_text_content(text, None)

        return MimeMode.CODE_LOG, "Unclassified QMimeData"

    @classmethod
    def _classify_from_header_and_name(cls, header: bytes, filename: str) -> Tuple[MimeMode, str]:
        """Examine 256-byte magic numbers and filename."""
        lower_name = filename.lower()
        suffix = os.path.splitext(lower_name)[1]

        # 1. Exact Infra Filenames
        if lower_name in cls._INFRA_NAMES or lower_name.startswith("docker-compose"):
            return MimeMode.INFRA, f"Container / Compose Config: {filename}"

        # 2. Header Magic Bytes - Binary Executables
        if header.startswith(cls._MAGIC_ELF):
            return MimeMode.BINARY, f"ELF Executable / Library: {filename}"
        if header.startswith(cls._MAGIC_MZ):
            return MimeMode.BINARY, f"PE Portable Executable: {filename}"
        if header.startswith((cls._MAGIC_MACHO_32, cls._MAGIC_MACHO_64, cls._MAGIC_MACHO_FAT)):
            return MimeMode.BINARY, f"Mach-O Binary: {filename}"

        # 3. Header Magic Bytes - Images
        if header.startswith(cls._MAGIC_PNG):
            return MimeMode.IMAGE, f"PNG Image: {filename}"
        if header.startswith(cls._MAGIC_JPEG):
            return MimeMode.IMAGE, f"JPEG Image: {filename}"
        if header.startswith(cls._MAGIC_BMP):
            return MimeMode.IMAGE, f"BMP Image: {filename}"
        if header.startswith(cls._MAGIC_RIFF) and len(header) >= 12 and header[8:12] == cls._MAGIC_WEBP:
            return MimeMode.IMAGE, f"WebP Image: {filename}"

        # 4. Header Magic Bytes - Datasets
        if header.startswith(cls._MAGIC_PARQUET):
            return MimeMode.DATASET, f"Apache Parquet Dataset: {filename}"
        if header.startswith(cls._MAGIC_SQLITE):
            return MimeMode.DATASET, f"SQLite Database: {filename}"

        # 5. Header Magic Bytes - ML Models
        if header.startswith(cls._MAGIC_HDF5):
            return MimeMode.ML_MODEL, f"HDF5 / Keras Model: {filename}"

        # Safetensors: First 8 bytes are little-endian unsigned 64-bit int header length
        if len(header) >= 8:
            try:
                hdr_len = struct.unpack("<Q", header[:8])[0]
                if 0 < hdr_len < 100_000_000 and len(header) > 8 and (header[8:9] == b"{" or b"__metadata__" in header[:256]):
                    return MimeMode.ML_MODEL, f"Safetensors Model: {filename}"
            except Exception:
                pass

        # Pickle magic (0x80 followed by protocol 2, 3, 4, 5)
        if len(header) >= 2 and header[0] == 0x80 and header[1] in (2, 3, 4, 5):
            if suffix in cls._ML_EXTS or "model" in lower_name:
                return MimeMode.ML_MODEL, f"Pickle ML Model: {filename}"

        # PyTorch Zip Archive (.pt / .pth / .zip)
        if header.startswith(cls._MAGIC_ZIP) and (suffix in {".pt", ".pth", ".onnx", ".bin"} or "model" in lower_name):
            return MimeMode.ML_MODEL, f"PyTorch Checkpoint: {filename}"

        # 6. Suffix-based routing
        if suffix in cls._IMAGE_EXTS:
            return MimeMode.IMAGE, f"Image File: {filename}"
        if suffix in cls._DATASET_EXTS:
            return MimeMode.DATASET, f"Dataset File: {filename}"
        if suffix in cls._ML_EXTS:
            return MimeMode.ML_MODEL, f"Machine Learning Model: {filename}"
        if suffix in cls._BINARY_EXTS:
            return MimeMode.BINARY, f"Compiled Binary: {filename}"
        if suffix in cls._GIT_EXTS:
            return MimeMode.GIT_PATCH, f"Git Patch / Diff: {filename}"
        if suffix in cls._INFRA_EXTS or suffix in {".yaml", ".yml"} and any(k in lower_name for k in ["k8s", "docker", "deploy", "helm", "ci"]):
            return MimeMode.INFRA, f"Infrastructure Config: {filename}"

        # YAML without explicit infra name
        if suffix in {".yaml", ".yml"}:
            return MimeMode.INFRA, f"YAML Specification: {filename}"

        # JSON files can be Datasets or Schemas
        if suffix == ".json":
            # If header looks like an array of objects or table records -> DATASET
            stripped = header.lstrip()
            if stripped.startswith(b"[") or b'"records"' in header or b'"data"' in header:
                return MimeMode.DATASET, f"JSON Dataset: {filename}"
            return MimeMode.CODE_LOG, f"JSON File: {filename}"

        # Code / Logs
        if suffix in cls._CODE_LOG_EXTS:
            return MimeMode.CODE_LOG, f"Source Code / Log: {filename}"

        # Default fallback
        return MimeMode.CODE_LOG, f"Document: {filename}"

    @classmethod
    def _classify_text_content(cls, text: str, hint_filename: Optional[str] = None) -> Tuple[MimeMode, str]:
        """Classify raw text snippets in-memory."""
        if hint_filename:
            res_mode, res_desc = cls._classify_from_header_and_name(text[:256].encode("utf-8", "ignore"), hint_filename)
            if res_mode != MimeMode.CODE_LOG:
                return res_mode, res_desc

        stripped = text.strip()
        lines = stripped.splitlines()
        first_line = lines[0].strip() if lines else ""

        # 1. Git Patch / Diff
        if (
            first_line.startswith("diff --git")
            or first_line.startswith("--- a/")
            or first_line.startswith("Index: ")
            or first_line.startswith("From ") and "mon " in first_line.lower()
            or any(l.startswith("@@ -") for l in lines[:5])
        ):
            return MimeMode.GIT_PATCH, "Unified Diff / Patch Text"

        # 2. Infrastructure
        if (
            first_line.upper().startswith("FROM ")
            or "apiVersion:" in text[:500]
            or "services:" in text[:500] and "image:" in text[:500]
            or 'resource "' in text[:500] and "{" in text[:500]
        ):
            return MimeMode.INFRA, "Infrastructure Configuration Text"

        # 3. Dataset (CSV or TSV format detection)
        if len(lines) >= 2:
            first_commas = first_line.count(",")
            second_commas = lines[1].count(",")
            if first_commas >= 2 and first_commas == second_commas:
                return MimeMode.DATASET, "CSV Tabular Stream"
            first_tabs = first_line.count("\t")
            second_tabs = lines[1].count("\t")
            if first_tabs >= 2 and first_tabs == second_tabs:
                return MimeMode.DATASET, "TSV Tabular Stream"

        # 4. JSON Dataset vs Code
        if stripped.startswith("[") and stripped.endswith("]") and "{" in stripped:
            return MimeMode.DATASET, "JSON Records Dataset"

        # 5. Stack Trace / Crash Log
        if "Traceback (most recent call last):" in text or "Exception in thread" in text:
            return MimeMode.CODE_LOG, "Crash Stack Trace"

        return MimeMode.CODE_LOG, "Plain Text / Code Stream"
