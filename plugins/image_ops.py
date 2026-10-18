"""
Mode 1: IMAGE Operations Plugin for ArcP.
Provides CV Smart Blur, Stego & EXIF Nuke, Tensor/OCR Extract, and WebP Ultra-Compress.
Strictly in-memory via OpenCV, NumPy, and Pillow.
"""
from __future__ import annotations

import base64
import io
import os
import re
import time
from typing import Any, Dict, Optional, Tuple

from PIL import Image

from core.mime_router import MimeMode
from plugins.base_plugin import (
    PipeResult,
    RadialAction,
    SliceConfig,
    SubSliceConfig,
    lazy_import,
)

cv2 = lazy_import("cv2")
np = lazy_import("numpy")
pytesseract = lazy_import("pytesseract")


class ImageOpsPlugin(RadialAction):
    """Polymorphic Image Operations Plugin."""

    def __init__(self) -> None:
        super().__init__(MimeMode.IMAGE, "Image Operations")
        self._init_slices()
        self._face_cascade = None

    @property
    def face_cascade(self) -> Any:
        if self._face_cascade is None and cv2:
            try:
                cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
                if os.path.exists(cascade_path):
                    self._face_cascade = cv2.CascadeClassifier(cascade_path)
            except Exception:
                self._face_cascade = None
        return self._face_cascade

    def _init_slices(self) -> None:
        self.slices[1] = SliceConfig(
            slice_id=1,
            name="CV Smart Blur",
            description="AI/CV face & PII text blurring in RAM",
        )
        self.slices[2] = SliceConfig(
            slice_id=2,
            name="Stego/EXIF Nuke",
            description="Strip metadata & apply LSB noise perturbation",
        )
        self.slices[3] = SliceConfig(
            slice_id=3,
            name="OCR / Tensor Extract",
            description="Extract text or morphological table/tensor summary",
        )
        self.slices[4] = SliceConfig(
            slice_id=4,
            name="WebP Compress",
            description="Ultra-compress or transpile to WebP/Data URI",
            sub_slices=[
                SubSliceConfig("webp_lossless", "WebP Lossless", "Lossless WebP compression"),
                SubSliceConfig("png_quant", "PNG Quantized", "8-bit adaptive palette quantization"),
                SubSliceConfig("data_uri", "Base64 Data URI", "Base64 encoded inline Data URI string"),
            ],
        )

    def execute(
        self,
        payload: Any,
        slice_id: int,
        sub_option: Optional[str] = None,
    ) -> PipeResult:
        start_time = time.perf_counter()
        raw_bytes = self.read_payload_bytes(payload)

        if slice_id == 1:
            res_data, count = self._cv_smart_blur(raw_bytes)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=res_data,
                action_name="CV Smart Blur",
                mode=self.mode,
                latency_ms=latency,
                secrets_blocked=count,
                bytes_streamed=len(res_data),
                details={"blurred_regions": count},
            )

        elif slice_id == 2:
            res_data = self._stego_exif_nuke(raw_bytes)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=res_data,
                action_name="Stego & EXIF Nuke",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(res_data),
                details={"metadata_stripped": True, "lsb_perturbed": True},
            )

        elif slice_id == 3:
            markdown_out = self._ocr_tensor_extract(raw_bytes)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=markdown_out,
                action_name="OCR / Tensor Extract",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(markdown_out.encode("utf-8")),
                details={"format": "markdown"},
            )

        elif slice_id == 4:
            sub = sub_option or "webp_lossless"
            res_data, content_type = self._webp_ultra_compress(raw_bytes, sub)
            latency = (time.perf_counter() - start_time) * 1000.0
            is_str = isinstance(res_data, str)
            b_count = len(res_data.encode("utf-8")) if is_str else len(res_data)
            return PipeResult(
                data=res_data,
                action_name=f"Compress ({sub})",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=b_count,
                details={"sub_option": sub, "content_type": content_type},
            )

        raise ValueError(f"Invalid slice_id {slice_id} for ImageOpsPlugin")

    def _cv_smart_blur(self, raw_bytes: bytes) -> Tuple[bytes, int]:
        """Apply Gaussian blur to detected faces and sensitive text regions."""
        if cv2 is None:
            # Fallback using PIL
            pil_img = Image.open(io.BytesIO(raw_bytes)).convert("RGB")
            out_buf = io.BytesIO()
            pil_img.save(out_buf, format="PNG")
            return out_buf.getvalue(), 0

        # Decode via OpenCV strictly in RAM
        nparr = np.frombuffer(raw_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return raw_bytes, 0

        h, w = img.shape[:2]
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        redactions = 0

        # 1. Face Detection
        cascade = self.face_cascade
        if cascade is not None:
            try:
                faces = cascade.detectMultiScale(
                    gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30)
                )
                for (x, y, fw, fh) in faces:
                    roi = img[y : y + fh, x : x + fw]
                    ksize = max(15, (fw // 3) | 1)
                    blurred = cv2.GaussianBlur(roi, (ksize, ksize), 30)
                    img[y : y + fh, x : x + fw] = blurred
                    redactions += 1
            except Exception:
                pass

        # 2. Text / Sensitive Region Heuristic via Morphological Gradient
        # Captures dense text lines (emails, keys, IP addresses)
        try:
            grad_kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (9, 3))
            grad = cv2.morphologyEx(gray, cv2.MORPH_GRADIENT, grad_kernel)
            _, thresh = cv2.threshold(grad, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
            close_kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (21, 5))
            connected = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, close_kernel)

            contours, _ = cv2.findContours(connected, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            for cnt in contours:
                x, y, cw, ch = cv2.boundingRect(cnt)
                aspect_ratio = cw / float(ch + 1e-5)
                area = cw * ch
                # Target text-like bounding boxes (aspect ratio > 2, bounded area)
                if aspect_ratio > 2.0 and 800 < area < (h * w * 0.15) and ch < (h * 0.2):
                    roi = img[y : y + ch, x : x + cw]
                    ksize = max(11, (ch // 2) | 1)
                    blurred = cv2.GaussianBlur(roi, (ksize, ksize), 20)
                    img[y : y + ch, x : x + cw] = blurred
                    redactions += 1
        except Exception:
            pass

        success, encoded_buf = cv2.imencode(".png", img)
        if success:
            return encoded_buf.tobytes(), redactions
        return raw_bytes, redactions

    def _stego_exif_nuke(self, raw_bytes: bytes) -> bytes:
        """Strip all EXIF/metadata and perturb LSBs by +-1 to destroy steganographic payloads."""
        # Load through PIL to strip all metadata containers
        pil_img = Image.open(io.BytesIO(raw_bytes)).convert("RGB")
        pixel_array = np.array(pil_img, dtype=np.int16)

        # LSB perturbation: random noise in {-1, 0, 1}
        rng = np.random.default_rng(seed=42)
        noise = rng.integers(-1, 2, size=pixel_array.shape, endpoint=True, dtype=np.int16)
        perturbed = np.clip(pixel_array + noise, 0, 255).astype(np.uint8)

        # Reconstruct clean PIL image without EXIF or headers
        clean_img = Image.fromarray(perturbed, mode="RGB")
        out_buf = io.BytesIO()
        clean_img.save(out_buf, format="PNG", optimize=True)
        return out_buf.getvalue()

    def _ocr_tensor_extract(self, raw_bytes: bytes) -> str:
        """Extract OCR text if pytesseract exists, else morphological table & tensor summary."""
        pil_img = Image.open(io.BytesIO(raw_bytes))
        width, height = pil_img.size
        mode = pil_img.mode

        ocr_text = ""
        ocr_engine_used = False

        if pytesseract is not None:
            try:
                ocr_text = pytesseract.image_to_string(pil_img).strip()
                ocr_engine_used = True
            except Exception:
                ocr_text = ""

        # Compute tensor statistics in NumPy
        arr = np.array(pil_img.convert("RGB"))
        mean_rgb = arr.mean(axis=(0, 1)).round(1)
        std_rgb = arr.std(axis=(0, 1)).round(1)

        # Morphological table & structure detection via OpenCV
        detected_structures = []
        if cv2 is not None:
            try:
                gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
                # Horizontal lines
                h_kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (max(10, width // 25), 1))
                h_lines = cv2.morphologyEx(gray, cv2.MORPH_OPEN, h_kernel)
                # Vertical lines
                v_kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (1, max(10, height // 25)))
                v_lines = cv2.morphologyEx(gray, cv2.MORPH_OPEN, v_kernel)
                table_grid = cv2.add(h_lines, v_lines)
                cnts, _ = cv2.findContours(table_grid, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                for c in cnts[:10]:
                    x, y, w, h = cv2.boundingRect(c)
                    if w > 40 and h > 20:
                        detected_structures.append(f"- Grid Cell: `[x={x}, y={y}, w={w}, h={h}]`")
            except Exception:
                pass

        # Build Markdown Card
        lines = [
            "# ArcP Visual Tensor & OCR Extraction",
            "",
            "### Image Metadata & Tensor Properties",
            f"- **Resolution:** `{width} x {height}` px",
            f"- **Channels / Mode:** `{mode}` ({arr.shape})",
            f"- **Mean RGB:** `R={mean_rgb[0]}, G={mean_rgb[1]}, B={mean_rgb[2]}`",
            f"- **StdDev RGB:** `R={std_rgb[0]}, G={std_rgb[1]}, B={std_rgb[2]}`",
            "",
        ]

        if ocr_engine_used and ocr_text:
            lines.extend([
                "### Extracted OCR Text Content",
                "```text",
                ocr_text,
                "```",
                "",
            ])
        else:
            lines.extend([
                "### Layout & Morphological Structural Analysis",
                f"- **Grid Cells Detected:** `{len(detected_structures)}`",
            ])
            lines.extend(detected_structures or ["- No explicit tabular grids detected."])
            lines.append("")

        return "\n".join(lines)

    def _webp_ultra_compress(self, raw_bytes: bytes, sub_option: str) -> Tuple[Any, str]:
        """Compress in-memory to WebP, Quantized PNG, or Base64 Data URI."""
        pil_img = Image.open(io.BytesIO(raw_bytes))

        if sub_option == "webp_lossless":
            out_buf = io.BytesIO()
            pil_img.save(out_buf, format="WEBP", lossless=True, quality=100)
            return out_buf.getvalue(), "image/webp"

        elif sub_option == "png_quant":
            out_buf = io.BytesIO()
            quantized = pil_img.convert("RGBA").quantize(colors=256, method=Image.Quantize.MEDIANCUT)
            quantized.save(out_buf, format="PNG", optimize=True)
            return out_buf.getvalue(), "image/png"

        elif sub_option == "data_uri":
            out_buf = io.BytesIO()
            pil_img.save(out_buf, format="WEBP", quality=85)
            b64_str = base64.b64encode(out_buf.getvalue()).decode("ascii")
            data_uri = f"data:image/webp;base64,{b64_str}"
            return data_uri, "text/plain"

        # Fallback WebP
        out_buf = io.BytesIO()
        pil_img.save(out_buf, format="WEBP", quality=80)
        return out_buf.getvalue(), "image/webp"
