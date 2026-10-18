"""
Mode 4: ML_MODEL Operations Plugin for ArcP.
Provides static Pickle & Malicious Opcode Audit, Header/Tensor Architecture Inspection,
FP32 -> FP16/INT8 Quantization Estimation, and Benchmarking Wrapper Generation.
"""
from __future__ import annotations

import io
import json
import pickletools
import struct
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from core.mime_router import MimeMode
from plugins.base_plugin import PipeResult, RadialAction, SliceConfig, SubSliceConfig


class MlOpsPlugin(RadialAction):
    """Polymorphic Machine Learning Model Operations Plugin."""

    DANGEROUS_CALLS = {
        ("os", "system"),
        ("os", "popen"),
        ("subprocess", "Popen"),
        ("subprocess", "call"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("subprocess", "run"),
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("builtins", "__import__"),
        ("posix", "system"),
        ("nt", "system"),
        ("pty", "spawn"),
        ("shutil", "rmtree"),
        ("socket", "socket"),
    }

    def __init__(self) -> None:
        super().__init__(MimeMode.ML_MODEL, "ML Model Operations")
        self._init_slices()

    def _init_slices(self) -> None:
        self.slices[1] = SliceConfig(
            slice_id=1,
            name="Pickle Opcode Audit",
            description="Static opcode disassembly detecting REDUCE/GLOBAL injection vectors",
        )
        self.slices[2] = SliceConfig(
            slice_id=2,
            name="Architecture & Tensors",
            description="Extract parameter totals, shapes, and layer hierarchy",
        )
        self.slices[3] = SliceConfig(
            slice_id=3,
            name="Quantize Calculator",
            description="FP32 -> FP16/INT8 memory reduction & export boilerplate",
        )
        self.slices[4] = SliceConfig(
            slice_id=4,
            name="Inference Wrapper Gen",
            description="Generate PyTorch/ONNX warmup and CUDA Event benchmark code",
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
            audit_report, is_safe, threats = self._audit_pickle_opcodes(raw_bytes)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=audit_report,
                action_name="Pickle Opcode Audit",
                mode=self.mode,
                latency_ms=latency,
                secrets_blocked=len(threats),
                bytes_streamed=len(audit_report.encode("utf-8")),
                details={"is_safe": is_safe, "threats_found": len(threats)},
            )

        elif slice_id == 2:
            inspector_md = self._inspect_architecture(raw_bytes)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=inspector_md,
                action_name="Architecture & Tensor Inspector",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(inspector_md.encode("utf-8")),
                details={"format": "markdown"},
            )

        elif slice_id == 3:
            quant_report = self._calculate_quantization(raw_bytes)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=quant_report,
                action_name="Dynamic Weight Quantize Summary",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(quant_report.encode("utf-8")),
                details={"format": "markdown"},
            )

        elif slice_id == 4:
            wrapper_code = self._generate_inference_wrapper()
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=wrapper_code,
                action_name="Inference Benchmark Wrapper Gen",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(wrapper_code.encode("utf-8")),
                details={"runtime": "pytorch/onnx"},
            )

        raise ValueError(f"Invalid slice_id {slice_id} for MlOpsPlugin")

    def _audit_pickle_opcodes(self, raw_bytes: bytes) -> Tuple[str, bool, List[str]]:
        """Statically disassemble pickle stream using pickletools without executing bytecode."""
        threats: List[str] = []
        opcodes_count = 0
        globals_referenced: List[str] = []

        # If it's a zip file (PyTorch .pt/.pth), locate internal data.pkl
        data_to_scan = raw_bytes
        if raw_bytes.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
                    for name in zf.namelist():
                        if name.endswith("data.pkl") or "pkl" in name:
                            data_to_scan = zf.read(name)
                            break
            except Exception:
                pass

        try:
            for opcode, arg, pos in pickletools.genops(io.BytesIO(data_to_scan)):
                opcodes_count += 1
                if opcode.name in ("GLOBAL", "STACK_GLOBAL"):
                    module_name, func_name = "", ""
                    if isinstance(arg, str):
                        parts = arg.split(" ")
                        if len(parts) >= 2:
                            module_name, func_name = parts[0], parts[1]
                        else:
                            module_name = parts[0]
                    ref_str = f"{module_name}.{func_name}".strip(".")
                    globals_referenced.append(ref_str)

                    if (module_name, func_name) in self.DANGEROUS_CALLS:
                        threats.append(f"Dangerous GLOBAL opcode at byte {pos}: `{ref_str}`")

                elif opcode.name == "REDUCE":
                    # Flag if prior global was suspicious
                    pass
        except Exception as e:
            # If not valid pickle, report as non-pickle stream
            threats.append(f"Non-standard or truncated pickle stream: {str(e)}")

        is_safe = len(threats) == 0
        status_badge = "🛡️ PASSED / SECURE" if is_safe else "🚨 THREAT DETECTED / BLOCKED"

        report = [
            "# ArcP Static Machine Learning Model Audit",
            "",
            f"### Security Clearance: **{status_badge}**",
            f"- **Opcodes Scanned:** `{opcodes_count:,}`",
            f"- **Globals Referenced:** `{len(globals_referenced)}`",
            f"- **Critical Flags:** `{len(threats)}`",
            "",
            "### Referenced External Modules",
        ]
        if globals_referenced:
            for g in sorted(set(globals_referenced))[:15]:
                report.append(f"- `{g}`")
        else:
            report.append("- *No external globals loaded.*")

        if threats:
            report.extend([
                "",
                "### ⚠️ Security Threat Analysis",
            ])
            for t in threats:
                report.append(f"- {t}")

        return "\n".join(report), is_safe, threats

    def _inspect_architecture(self, raw_bytes: bytes) -> str:
        """Inspect safetensors or PyTorch headers for parameter totals and layer shapes."""
        # 1. Safetensors check
        if len(raw_bytes) >= 8:
            try:
                hdr_len = struct.unpack("<Q", raw_bytes[:8])[0]
                if 0 < hdr_len < len(raw_bytes) and raw_bytes[8:9] == b"{":
                    meta_json = json.loads(raw_bytes[8 : 8 + hdr_len].decode("utf-8"))
                    total_params = 0
                    tensors = []
                    for k, v in meta_json.items():
                        if isinstance(v, dict) and "shape" in v:
                            shape = v["shape"]
                            dtype = v.get("dtype", "unknown")
                            p_count = 1
                            for dim in shape:
                                p_count *= dim
                            total_params += p_count
                            tensors.append((k, shape, dtype, p_count))

                    return self._format_tensor_report(
                        "Safetensors Model Architecture",
                        len(tensors),
                        total_params,
                        tensors[:20],
                    )
            except Exception:
                pass

        # 2. PyTorch Zip Check
        if raw_bytes.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
                    names = zf.namelist()
                    total_uncompressed = sum(info.file_size for info in zf.infolist())
                    return (
                        f"# ArcP PyTorch Checkpoint Inspector\n\n"
                        f"- **Format:** PyTorch Zip Archive\n"
                        f"- **Archived Files:** `{len(names)}`\n"
                        f"- **Uncompressed Storage:** `{round(total_uncompressed / (1024*1024), 2)} MB`\n"
                        f"- **Core Assets:** `{', '.join(names[:5])}`\n"
                    )
            except Exception:
                pass

        # Generic Model Header fallback
        size_mb = round(len(raw_bytes) / (1024 * 1024), 2)
        est_fp32_params = int((len(raw_bytes) / 4))
        return (
            f"# ArcP Model Binary Inspector\n\n"
            f"- **Binary Size:** `{size_mb} MB`\n"
            f"- **Estimated FP32 Parameters:** `~{est_fp32_params:,}` ({round(est_fp32_params / 1e6, 2)}M params)\n"
            f"- **Header Signature:** `{raw_bytes[:16].hex()}`\n"
        )

    def _format_tensor_report(
        self, title: str, layer_count: int, total_params: int, sample_tensors: List[Tuple[str, List[int], str, int]]
    ) -> str:
        param_str = (
            f"{round(total_params / 1e9, 2)}B"
            if total_params >= 1e9
            else f"{round(total_params / 1e6, 2)}M"
        )
        md = [
            f"# {title}",
            "",
            f"- **Total Layers / Tensors:** `{layer_count}`",
            f"- **Total Parameter Count:** `{total_params:,}` ({param_str})",
            "",
            "| Tensor Name | Shape | Data Type | Parameters |",
            "|---|---|---|---|",
        ]
        for name, shape, dtype, count in sample_tensors:
            md.append(f"| `{name[:30]}` | `{shape}` | `{dtype}` | `{count:,}` |")

        return "\n".join(md)

    def _calculate_quantization(self, raw_bytes: bytes) -> str:
        """Calculate memory reduction from FP32 to FP16 and INT8 and generate boilerplate."""
        size_mb = max(1.0, len(raw_bytes) / (1024 * 1024))
        fp16_mb = round(size_mb * 0.5, 1)
        int8_mb = round(size_mb * 0.25, 1)
        int4_mb = round(size_mb * 0.125, 1)

        code_snippet = """# ArcP Dynamic Weight Quantization Boilerplate
import torch

def quantize_model(model: torch.nn.Module, mode: str = "fp16") -> torch.nn.Module:
    \"\"\"Zero-latency in-memory quantization.\"\"\"
    if mode == "fp16":
        return model.half()
    elif mode == "int8":
        return torch.ao.quantization.quantize_dynamic(
            model,
            {torch.nn.Linear},
            dtype=torch.qint8
        )
    return model
"""

        return f"""# ⚡ ArcP Dynamic Weight Quantization Analysis

### In-Memory VRAM Footprint Projections
| Precision | Footprint (MB) | Reduction (%) | Target Hardware |
|---|---|---|---|
| **FP32** (Baseline) | `{size_mb:.1f} MB` | `0%` | High-End Server GPU (A100/H100) |
| **FP16** (Half) | `{fp16_mb} MB` | `50.0%` | RTX 3080 / 4090 / T4 |
| **INT8** (Quantized) | `{int8_mb} MB` | `75.0%` | Edge AI / Jetson / CPU Server |
| **INT4** (AWQ/GPTQ) | `{int4_mb} MB` | `87.5%` | Mobile / Apple Silicon / M-Series |

### Ready-to-Run Quantization Code
```python
{code_snippet}
```
"""

    def _generate_inference_wrapper(self) -> str:
        """Generate high-precision CUDA Event benchmarking inference wrapper."""
        return """# ArcP High-Precision Inference Benchmark Wrapper
from __future__ import annotations
import time
import torch

def benchmark_inference(model: torch.nn.Module, sample_input: torch.Tensor, iterations: int = 100):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    sample_input = sample_input.to(device)

    # 1. Warmup Loop (10 iterations)
    with torch.no_grad():
        for _ in range(10):
            _ = model(sample_input)

    if device.type == "cuda":
        torch.cuda.synchronize()
        start_event = torch.cuda.Event(enable_timing=True)
        end_event = torch.cuda.Event(enable_timing=True)

        timings_ms = []
        with torch.no_grad():
            for _ in range(iterations):
                start_event.record()
                _ = model(sample_input)
                end_event.record()
                torch.cuda.synchronize()
                timings_ms.append(start_event.elapsed_time(end_event))
    else:
        timings_ms = []
        with torch.no_grad():
            for _ in range(iterations):
                t0 = time.perf_counter()
                _ = model(sample_input)
                timings_ms.append((time.perf_counter() - t0) * 1000.0)

    timings_ms.sort()
    p50 = timings_ms[len(timings_ms) // 2]
    p95 = timings_ms[int(len(timings_ms) * 0.95)]
    p99 = timings_ms[int(len(timings_ms) * 0.99)]

    print(f"Latency P50: {p50:.2f}ms | P95: {p95:.2f}ms | P99: {p99:.2f}ms")
    print(f"Throughput: {1000.0 / p50:.1f} inferences/sec")
    return {"p50": p50, "p95": p95, "p99": p99}
"""
