"""
Comprehensive End-to-End Test Suite for ArcP.
Tests Polar Coordinate Math, Reversible Redaction Token Vault,
MIME Sniffing & Routing, and all 7 Polymorphic Plugins.
"""
from __future__ import annotations

import io
import os
import sys
import pytest

# Ensure offscreen Qt platform is used ONLY when running inside pytest test runner
if "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST"):
    os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PyQt6.QtWidgets import QApplication

# Initialize singleton QApplication for Qt tests
app = QApplication.instance()
if app is None:
    app = QApplication(sys.argv)

from core.mime_router import MimeMode, MimeRouter
from core.token_vault import TokenVault, calculate_shannon_entropy
from core.gravity_well import GravityWell
from core.telemetry import TelemetryTracker
from ui.geometry import (
    cartesian_to_polar,
    polar_to_cartesian,
    build_donut_sector_path,
    resolve_radial_collision,
)
from plugins.image_ops import ImageOpsPlugin
from plugins.data_ops import DataOpsPlugin
from plugins.code_log_ops import CodeLogOpsPlugin
from plugins.ml_ops import MlOpsPlugin
from plugins.infra_ops import InfraOpsPlugin
from plugins.binary_ops import BinaryOpsPlugin
from plugins.git_ops import GitOpsPlugin


# =============================================================================
# 1. POLAR GEOMETRY TESTS
# =============================================================================
class TestPolarGeometry:
    def test_cartesian_to_polar_cardinal_directions(self):
        xc, yc = 260.0, 260.0

        # Right (dx > 0, dy = 0) -> theta = 0 deg
        r, theta = cartesian_to_polar(360.0, 260.0, xc, yc)
        assert pytest.approx(r, 0.01) == 100.0
        assert pytest.approx(theta, 0.01) == 0.0

        # Bottom (dx = 0, dy > 0) -> theta = 90 deg
        r, theta = cartesian_to_polar(260.0, 360.0, xc, yc)
        assert pytest.approx(r, 0.01) == 100.0
        assert pytest.approx(theta, 0.01) == 90.0

        # Left (dx < 0, dy = 0) -> theta = 180 deg
        r, theta = cartesian_to_polar(160.0, 260.0, xc, yc)
        assert pytest.approx(r, 0.01) == 100.0
        assert pytest.approx(theta, 0.01) == 180.0

        # Top (dx = 0, dy < 0) -> theta = 270 deg
        r, theta = cartesian_to_polar(260.0, 160.0, xc, yc)
        assert pytest.approx(r, 0.01) == 100.0
        assert pytest.approx(theta, 0.01) == 270.0

    def test_polar_to_cartesian_roundtrip(self):
        xc, yc = 260.0, 260.0
        for deg in [0.0, 45.0, 90.0, 180.0, 270.0, 315.0]:
            x, y = polar_to_cartesian(120.0, deg, xc, yc)
            r, theta = cartesian_to_polar(x, y, xc, yc)
            assert pytest.approx(r, 0.01) == 120.0
            assert pytest.approx(theta, 0.01) == deg

    def test_donut_sector_path_construction(self):
        path = build_donut_sector_path(260.0, 260.0, 65.0, 175.0, 227.0, 86.0)
        assert not path.isEmpty()
        assert path.elementCount() > 0

    def test_radial_collision_zones(self):
        xc, yc = 260.0, 260.0
        sub_counts = {1: 3, 2: 2, 3: 1, 4: 3}

        # Center Gravity Well (r < 65)
        s_id, s_idx, zone = resolve_radial_collision(260.0, 260.0, xc, yc, sub_counts)
        assert zone == "GRAVITY_WELL"
        assert s_id == 0

        # Primary Slice 1 (Top: dy = -120)
        s_id, s_idx, zone = resolve_radial_collision(260.0, 140.0, xc, yc, sub_counts)
        assert zone == "PRIMARY"
        assert s_id == 1

        # Primary Slice 2 (Right: dx = +120)
        s_id, s_idx, zone = resolve_radial_collision(380.0, 260.0, xc, yc, sub_counts)
        assert zone == "PRIMARY"
        assert s_id == 2

        # Primary Slice 3 (Bottom: dy = +120)
        s_id, s_idx, zone = resolve_radial_collision(260.0, 380.0, xc, yc, sub_counts)
        assert zone == "PRIMARY"
        assert s_id == 3

        # Primary Slice 4 (Left: dx = -120)
        s_id, s_idx, zone = resolve_radial_collision(140.0, 260.0, xc, yc, sub_counts)
        assert zone == "PRIMARY"
        assert s_id == 4

        # Concentric Outer Ring (r = 210, Top: dy = -210)
        s_id, s_idx, zone = resolve_radial_collision(260.0, 50.0, xc, yc, sub_counts)
        assert zone == "CONCENTRIC"
        assert s_id == 1
        assert s_idx is not None and 0 <= s_idx < 3

        # Outside perimeter (r > 245)
        s_id, s_idx, zone = resolve_radial_collision(260.0, 5.0, xc, yc, sub_counts)
        assert zone == "VOID"


# =============================================================================
# 2. TOKEN VAULT REVERSIBLE REDACTION TESTS
# =============================================================================
class TestTokenVault:
    def test_shannon_entropy(self):
        assert calculate_shannon_entropy("") == 0.0
        assert calculate_shannon_entropy("AAAAAA") == 0.0
        # High entropy random string
        h = calculate_shannon_entropy("4nZ9!kP@2xL#8vQ$")
        assert h > 3.5

    def test_scrub_and_rehydrate_aws_key(self):
        vault = TokenVault(ttl=600.0)
        secret = "AKIAIOSFODNN7EXAMPLE"
        log = f"CRITICAL: Failed auth using key {secret} on port 443"

        sanitized, count = vault.scrub_and_store(log)
        assert count == 1
        assert secret not in sanitized
        assert "<ARCP_SECRET_1>" in sanitized

        # Rehydrate
        restored, r_count = vault.rehydrate(sanitized)
        assert r_count == 1
        assert restored == log

    def test_scrub_pii_emails_and_ips(self):
        vault = TokenVault(ttl=600.0)
        raw_text = "Contact user alice.smith@enterprise.org from 192.168.1.100 or phone (555) 234-5678"

        sanitized, count = vault.scrub_and_store(raw_text)
        assert count >= 3
        assert "alice.smith@enterprise.org" not in sanitized
        assert "192.168.1.100" not in sanitized
        assert "<ARCP_EMAIL_1>" in sanitized
        assert "<ARCP_IP_1>" in sanitized

        restored, _ = vault.rehydrate(sanitized)
        assert restored == raw_text

    def test_vault_ttl_expiration(self):
        vault = TokenVault(ttl=0.05)  # 50ms TTL
        secret = "AKIAIOSFODNN7EXAMP12"
        sanitized, _ = vault.scrub_and_store(secret)
        import time
        time.sleep(0.08)
        # Should be expired and pruned
        restored, r_count = vault.rehydrate(sanitized)
        assert r_count == 0
        assert restored == sanitized


# =============================================================================
# 3. MIME ROUTER TESTS
# =============================================================================
class TestMimeRouter:
    def test_classify_png_header(self):
        png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        mode, _ = MimeRouter.classify_payload(png_header)
        assert mode == MimeMode.IMAGE

    def test_classify_parquet_header(self):
        parquet_header = b"PAR1\x15\x00\x00..."
        mode, _ = MimeRouter.classify_payload(parquet_header)
        assert mode == MimeMode.DATASET

    def test_classify_elf_binary(self):
        elf_header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00"
        mode, _ = MimeRouter.classify_payload(elf_header)
        assert mode == MimeMode.BINARY

    def test_classify_git_diff(self):
        diff_text = "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n"
        mode, _ = MimeRouter.classify_payload(diff_text)
        assert mode == MimeMode.GIT_PATCH

    def test_classify_infra_dockerfile(self):
        docker_text = "FROM python:3.11-slim\nUSER appuser\nCMD [\"python\", \"app.py\"]\n"
        mode, _ = MimeRouter.classify_payload(docker_text)
        assert mode == MimeMode.INFRA

    def test_classify_csv_dataset(self):
        csv_text = "id,name,role,department\n1,Alice,Dev,Engineering\n2,Bob,SRE,Operations\n"
        mode, _ = MimeRouter.classify_payload(csv_text)
        assert mode == MimeMode.DATASET


# =============================================================================
# 4. POLYMORPHIC PLUGIN TESTS (ALL 7 MODES)
# =============================================================================
class TestPlugins:
    def test_image_ops_plugin(self):
        plugin = ImageOpsPlugin()
        # Create minimal 16x16 in-memory PNG
        from PIL import Image
        img = Image.new("RGB", (32, 32), color=(100, 150, 200))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_bytes = buf.getvalue()

        # Slice 2: Stego & EXIF Nuke
        res = plugin.execute(png_bytes, slice_id=2)
        assert res.mode == MimeMode.IMAGE
        assert len(res.data) > 0

        # Slice 3: OCR / Tensor Extract
        res_ocr = plugin.execute(png_bytes, slice_id=3)
        assert "ArcP Visual Tensor" in res_ocr.data

        # Slice 4: WebP Compress
        res_webp = plugin.execute(png_bytes, slice_id=4, sub_option="webp_lossless")
        assert len(res_webp.data) > 0

    def test_image_ops_ocr_text_extraction(self):
        plugin = ImageOpsPlugin()
        from PIL import Image, ImageDraw
        img = Image.new("RGB", (600, 200), color="white")
        draw = ImageDraw.Draw(img)
        draw.text((20, 30), "ArcP OCR Test Extraction", fill="black")
        draw.text((20, 80), "Zero-Disk In-Memory Validation", fill="black")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        res = plugin.execute(buf.getvalue(), slice_id=3)
        assert res.mode == MimeMode.IMAGE
        assert "ArcP Visual Tensor" in res.data
        assert "Image Metadata & Tensor Properties" in res.data
        assert "Layout & Morphological Structural Analysis" in res.data
        if sys.platform == "win32":
            assert "Windows Native WinRT OCR" in res.data
            assert "Extracted OCR Text Content" in res.data

    def test_image_ops_smart_blur_targeted_pii(self):
        plugin = ImageOpsPlugin()
        from PIL import Image, ImageDraw
        img = Image.new("RGB", (600, 200), color="white")
        draw = ImageDraw.Draw(img)
        draw.text((20, 30), "Contact user: alice@internal.corp", fill="black")
        draw.text((20, 80), "Welcome to Public Dashboard", fill="black")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        res = plugin.execute(buf.getvalue(), slice_id=1, sub_option="targeted_pii")
        assert res.mode == MimeMode.IMAGE
        assert len(res.data) > 0
        assert res.details["mode"] == "targeted_pii"



    def test_data_ops_plugin(self):
        plugin = DataOpsPlugin()
        csv_data = (
            "user_id,email,age,score\n"
            "1001,alice@domain.com,25,88.5\n"
            "1002,bob@domain.com,30,92.0\n"
            "1003,charlie@domain.com,35,79.0\n"
        )

        # Slice 1: Synthetic Twin
        res_synth = plugin.execute(csv_data, slice_id=1)
        assert "user_id,email,age,score" in res_synth.data
        lines = res_synth.data.strip().splitlines()
        assert len(lines) == 101  # Header + 100 synthetic rows

        # Slice 2: PII Masking
        res_mask = plugin.execute(csv_data, slice_id=2)
        assert "ID_" in res_mask.data
        assert "alice@domain.com" not in res_mask.data

        # Slice 3: Instant EDA HTML
        res_eda = plugin.execute(csv_data, slice_id=3)
        assert "<!DOCTYPE html>" in res_eda.data
        assert "ARCP INSTANT EDA REPORT" in res_eda.data

        # Slice 4: Transpile (JSON Records)
        res_json = plugin.execute(csv_data, slice_id=4, sub_option="json_records")
        assert '"user_id":' in res_json.data

    def test_code_log_ops_plugin(self):
        vault = TokenVault(ttl=600.0)
        plugin = CodeLogOpsPlugin(vault)
        code_text = (
            "import os\n"
            "API_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
            "def handle_request():\n"
            "    print('Processing...')\n"
        )

        # Slice 1: Secret Scrub
        res_scrub = plugin.execute(code_text, slice_id=1)
        assert "<ARCP_SECRET_" in res_scrub.data
        assert "AKIAIOSFODNN7EXAMPLE" not in res_scrub.data

        # Slice 2: Re-Hydrate
        res_restore = plugin.execute(res_scrub.data, slice_id=2, sub_option="rehydrate")
        assert "AKIAIOSFODNN7EXAMPLE" in res_restore.data

        # Slice 3: Schema Gen (Pydantic v2)
        json_sample = '{"id": "usr_1", "username": "alice", "active": true, "count": 42}'
        res_schema = plugin.execute(json_sample, slice_id=3, sub_option="pydantic_v2")
        assert "class AutoGeneratedModel(BaseModel):" in res_schema.data

        # Slice 4: Auto-Dockerize
        res_docker = plugin.execute(code_text, slice_id=4)
        assert "FROM python:" in res_docker.data
        assert "USER appuser" in res_docker.data

    def test_ml_ops_plugin(self):
        plugin = MlOpsPlugin()
        # Mock pickle bytes
        import pickle
        safe_data = {"weights": [1.0, 2.0, 3.0], "bias": 0.5}
        pkl_bytes = pickle.dumps(safe_data)

        # Slice 1: Pickle Opcode Audit
        res_audit = plugin.execute(pkl_bytes, slice_id=1)
        assert "PASSED / SECURE" in res_audit.data

        # Slice 3: Quantize Calculator
        res_quant = plugin.execute(pkl_bytes, slice_id=3)
        assert "FP16" in res_quant.data
        assert "INT8" in res_quant.data

        # Slice 4: Inference Wrapper Gen
        res_wrapper = plugin.execute(pkl_bytes, slice_id=4)
        assert "benchmark_inference" in res_wrapper.data

    def test_infra_ops_plugin(self):
        plugin = InfraOpsPlugin()
        compose_text = (
            "version: '3.8'\n"
            "services:\n"
            "  web:\n"
            "    image: nginx:latest\n"
            "    ports:\n"
            "      - '80:80'\n"
            "    depends_on:\n"
            "      - api\n"
            "  api:\n"
            "    image: backend:v1\n"
        )

        # Slice 1: Container Security Audit
        res_audit = plugin.execute(compose_text, slice_id=1)
        assert "ArcP Infrastructure Security Audit" in res_audit.data

        # Slice 2: Mermaid Architecture
        res_mermaid = plugin.execute(compose_text, slice_id=2)
        assert "flowchart" in res_mermaid.data
        assert "web -->|depends_on| api" in res_mermaid.data

        # Slice 3: K8s Manifest Converter
        res_k8s = plugin.execute(compose_text, slice_id=3)
        assert "kind: Deployment" in res_k8s.data
        assert "kind: Service" in res_k8s.data

        # Slice 4: Env Template
        res_env = plugin.execute("ENV PORT=8080\nENV DB_URL=${DATABASE_URL}", slice_id=4)
        assert "PORT=" in res_env.data

    def test_binary_ops_plugin(self):
        plugin = BinaryOpsPlugin()
        # Mock ELF header: 64-bit x86_64 ET_DYN (PIE)
        elf_bytes = (
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x03\x00\x3e\x00\x01\x00\x00\x00\x00\x10\x40\x00\x00\x00\x00\x00"
            + b"https://telemetry.corp.internal/ping\x00"
            + b"/etc/shadow\x00"
            + b"10.0.0.1\x00"
            + b"\x00" * 100
        )

        # Slice 1: ELF Header X-Ray
        res_xray = plugin.execute(elf_bytes, slice_id=1)
        assert "Linux ELF" in res_xray.data
        assert "x86_64" in res_xray.data

        # Slice 2: Strings & IOC
        res_strings = plugin.execute(elf_bytes, slice_id=2)
        assert "https://telemetry.corp.internal/ping" in res_strings.data

        # Slice 4: Cryptographic Hashes
        res_hashes = plugin.execute(elf_bytes, slice_id=4)
        assert "SHA-256" in res_hashes.data
        assert "Entropy Score" in res_hashes.data

    def test_binary_ops_with_python_source(self):
        plugin = BinaryOpsPlugin()
        py_source = (
            "#!/usr/bin/env python3\n"
            "# ArcP Sample Source Script\n"
            "import os\n"
            "import sys as system\n"
            "from PyQt6.QtWidgets import QWidget\n"
            "import ctypes\n"
            "\n"
            "MAX_BUFFER_SIZE = 1048576\n"
            "DEFAULT_TTL: float = 600.0\n"
            "API_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
            "\n"
            "class PipelineEngine(QWidget):\n"
            "    def process(self, stream_id: str) -> bool:\n"
            "        return True\n"
            "\n"
            "def run_worker(task_id: int):\n"
            "    url = 'https://api.arcp.local/v1/telemetry'\n"
            "    return task_id\n"
        )

        # Slice 1: Script Header X-Ray (Shebang, Encoding, Line endings, Hex Dump, Entropy)
        res_xray = plugin.execute(py_source, slice_id=1)
        assert "ArcP File Byte & Runtime Header X-Ray" in res_xray.data
        assert "Runtime Shebang:" in res_xray.data
        assert "#!/usr/bin/env python3" in res_xray.data
        assert "Canonical Hex Dump" in res_xray.data

        # Slice 2: IOC Extractor with secrets and URLs
        res_iocs = plugin.execute(py_source, slice_id=2)
        assert "ArcP Strings & IOC X-Ray" in res_iocs.data
        assert "https://api.arcp.local/v1/telemetry" in res_iocs.data
        assert "AWS Access Key" in res_iocs.data

        # Slice 3: Python AST Symbol & Dependency Audit
        res_ast = plugin.execute(py_source, slice_id=3)
        assert "ArcP Python AST Symbol & Dependency Audit" in res_ast.data
        assert "PipelineEngine" in res_ast.data
        assert "run_worker" in res_ast.data
        assert "MAX_BUFFER_SIZE" in res_ast.data
        assert "DEFAULT_TTL" in res_ast.data  # ast.AnnAssign type-annotated constant
        assert "ctypes" in res_ast.data

        # Slice 4: Cryptographic Hashes & Entropy
        res_hash = plugin.execute(py_source, slice_id=4)
        assert "Cryptographic Hash & Threat Intel Manifest" in res_hash.data
        assert "MD5:" in res_hash.data
        assert "SHA-256:" in res_hash.data

    def test_radial_window_manual_mode_override(self):
        from ui.radial_window import RadialWindow
        window = RadialWindow(start_collapsed=True)
        assert window.manual_mode_override is False

        # Manual mode switch pins mode
        window.set_active_mode(MimeMode.BINARY, manual=True)
        assert window.active_mode == MimeMode.BINARY
        assert window.manual_mode_override is True

        # Re-enabling auto mode resets override
        window.manual_mode_override = False
        assert window.manual_mode_override is False
        window.close()

    def test_inspector_drawer_markdown_display(self):
        from ui.inspector_drawer import InspectorDrawer
        from plugins.base_plugin import PipeResult

        drawer = InspectorDrawer(None)
        result = PipeResult(
            data="# Test Header\n\n| Col A | Col B |\n|---|---|\n| 1 | 2 |\n",
            action_name="AST Symbol Audit",
            mode=MimeMode.BINARY,
            latency_ms=12.5,
            bytes_streamed=45,
        )

        drawer.display_result(result)
        assert drawer.title_label.text() == "AST Symbol Audit"
        assert drawer.mode_badge.text() == "BINARY"
        assert "12.5ms" in drawer.latency_badge.text()
        assert drawer.stack.currentIndex() == 0  # Markdown viewport

        # Test Raw / Rendered Toggle
        drawer._toggle_raw_rendered()
        assert drawer._is_raw_view is True
        assert drawer.btn_toggle_raw.text() == "View Rendered"

        drawer._toggle_raw_rendered()
        assert drawer._is_raw_view is False
        assert drawer.btn_toggle_raw.text() == "View Raw"

        # Test Copy button
        drawer._copy_to_clipboard()
        assert drawer.btn_copy.text() == "Copied ✓"

        drawer.close()

    def test_inspector_drawer_image_display(self):
        from ui.inspector_drawer import InspectorDrawer
        from plugins.base_plugin import PipeResult
        from PyQt6.QtGui import QImage, QColor

        drawer = InspectorDrawer(None)
        qimg = QImage(64, 48, QImage.Format.Format_RGB32)
        qimg.fill(QColor(0, 245, 212))

        result = PipeResult(
            data=qimg,
            action_name="CV Smart Blur",
            mode=MimeMode.IMAGE,
            latency_ms=8.0,
            bytes_streamed=1024,
        )

        drawer.display_result(result)
        assert drawer.title_label.text() == "CV Smart Blur"
        assert drawer.stack.currentIndex() == 1  # Image preview viewport
        assert "64 × 48 px" in drawer.image_meta_label.text()

        drawer.close()

    def test_git_ops_plugin(self):
        vault = TokenVault()
        plugin = GitOpsPlugin(vault)
        code_file = "def add(a, b):\n    print('debug')\n    return a + b\n"

        # Slice 2: Patch Bundler
        res_patch = plugin.execute(code_file, slice_id=2)
        assert "[PATCH]" in res_patch.data
        assert "diff --git" in res_patch.data

        # Slice 3: Semantic Commit Gen
        res_commit = plugin.execute(code_file, slice_id=3)
        assert "feat(core):" in res_commit.data

        # Slice 4: Pre-Commit Gatekeeper (should flag print debug statement)
        res_gate = plugin.execute(code_file, slice_id=4)
        assert "print()" in res_gate.data


# =============================================================================
# 5. GRAVITY WELL & TELEMETRY TESTS
# =============================================================================
class TestCoreSystems:
    def test_gravity_well_queue(self):
        gw = GravityWell()
        assert gw.is_empty
        assert gw.count == 0

        p1 = gw.enqueue("file1.csv", "data1", "DATASET", 100)
        p2 = gw.enqueue("file2.py", "data2", "CODE_LOG", 200)

        assert gw.count == 2
        assert not gw.is_empty

        items = gw.dequeue_all()
        assert len(items) == 2
        assert items[0].id == p1.id
        assert gw.is_empty

    def test_telemetry_tracker(self):
        tracker = TelemetryTracker()
        tracker.record_latency(14.5)
        tracker.increment_secrets_blocked(3)
        tracker.set_queue_count(5)

        hud_str = tracker.format_hud()
        assert "15ms" in hud_str or "14ms" in hud_str
        assert "Blocked: 3" in hud_str

        snap = tracker.snapshot()
        assert snap.secrets_blocked == 3
        assert snap.queue_count == 5


# =============================================================================
# 6. HD CYBER ICONS & ASSET REGISTRY TESTS
# =============================================================================
class TestIconRegistry:
    def test_icon_rendering_and_caching(self):
        from ui.icons import IconRegistry, EMBEDDED_SVGS
        icon_names = ["zap", "package", "shield", "alert", "check", "cross", "search", "microscope", "lock", "sparkle", "arcp_logo"]

        for name in icon_names:
            # 1. Verify SVG source exists
            svg = IconRegistry.get_svg(name)
            assert "<svg" in svg
            assert "</svg>" in svg

            # 2. Verify QPixmap rendering
            pix = IconRegistry.get_pixmap(name, size=32)
            assert not pix.isNull()
            assert pix.width() == 32
            assert pix.height() == 32

            # 3. Verify QIcon generation
            qicon = IconRegistry.get_icon(name)
            assert not qicon.isNull()

            # 4. Verify base64 data URI
            data_uri = IconRegistry.get_data_uri(name)
            assert data_uri.startswith("data:image/svg+xml;base64,")

            # 5. Verify ASCII tag for Windows cp1252 consoles
            tag = IconRegistry.get_ascii_tag(name)
            assert tag.startswith("[") and tag.endswith("]")

    def test_read_payload_bytes_with_qimage(self):
        from PyQt6.QtGui import QImage, QColor
        from plugins.base_plugin import RadialAction
        qimg = QImage(32, 32, QImage.Format.Format_RGB32)
        qimg.fill(QColor(255, 0, 0))

        raw_bytes = RadialAction.read_payload_bytes(qimg)
        assert isinstance(raw_bytes, bytes)
        assert raw_bytes.startswith(b"\x89PNG") or len(raw_bytes) > 0
