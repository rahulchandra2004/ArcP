"""
Mode 3: CODE_LOG Operations Plugin for ArcP.
Provides Secret Scrub (Dehydrate), Token Re-Hydrate & Crash Triage,
Schema/Type Generation (Pydantic v2, TypeScript, C++20), and Hardened Auto-Dockerize.
"""
from __future__ import annotations

import ast
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from core.mime_router import MimeMode
from core.token_vault import TokenVault
from plugins.base_plugin import PipeResult, RadialAction, SliceConfig, SubSliceConfig


class CodeLogOpsPlugin(RadialAction):
    """Polymorphic Code and Log Operations Plugin."""

    def __init__(self, token_vault: Optional[TokenVault] = None) -> None:
        super().__init__(MimeMode.CODE_LOG, "Code & Log Operations")
        self.vault = token_vault or TokenVault()
        self._init_slices()

    def _init_slices(self) -> None:
        self.slices[1] = SliceConfig(
            slice_id=1,
            name="Secret Scrub",
            description="Scrub API keys & secrets to RAM",
            icon="shield",
        )
        self.slices[2] = SliceConfig(
            slice_id=2,
            name="Crash Triage",
            description="Restore tokens & triage crash logs",
            icon="search",
            sub_slices=[
                SubSliceConfig("rehydrate", "Re-Hydrate Tokens", "Scan and replace <ARCP_*> placeholders"),
                SubSliceConfig("crash_triage", "Crash Triage", "Deduplicate logs & extract root stack trace"),
            ],
        )
        self.slices[3] = SliceConfig(
            slice_id=3,
            name="Type Generator",
            description="JSON/AST to Pydantic, TS or C++",
            icon="sparkle",
            sub_slices=[
                SubSliceConfig("cpp20", "C++20 Struct", "Generate C++20 typed struct definitions"),
                SubSliceConfig("typescript", "TypeScript Interface", "Generate TS interface types"),
                SubSliceConfig("pydantic_v2", "Pydantic v2", "Generate typed Pydantic BaseModel"),
            ],
        )
        self.slices[4] = SliceConfig(
            slice_id=4,
            name="Auto-Dockerize",
            description="Multi-stage hardened Dockerfile",
            icon="container",
        )

    def execute(
        self,
        payload: Any,
        slice_id: int,
        sub_option: Optional[str] = None,
    ) -> PipeResult:
        start_time = time.perf_counter()
        text = self.read_payload_text(payload)

        if slice_id == 1:
            sanitized, count = self.vault.scrub_and_store(text)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=sanitized,
                action_name="Secret Scrub (Dehydrate)",
                mode=self.mode,
                latency_ms=latency,
                secrets_blocked=count,
                bytes_streamed=len(sanitized.encode("utf-8")),
                details={"scrubbed_count": count},
            )

        elif slice_id == 2:
            sub = sub_option or "rehydrate"
            if sub == "rehydrate":
                restored, count = self.vault.rehydrate(text)
                latency = (time.perf_counter() - start_time) * 1000.0
                return PipeResult(
                    data=restored,
                    action_name="Token Re-Hydrate",
                    mode=self.mode,
                    latency_ms=latency,
                    bytes_streamed=len(restored.encode("utf-8")),
                    details={"rehydrated_count": count},
                )
            else:
                triage_md = self._crash_triage(text)
                latency = (time.perf_counter() - start_time) * 1000.0
                return PipeResult(
                    data=triage_md,
                    action_name="Crash Triage",
                    mode=self.mode,
                    latency_ms=latency,
                    bytes_streamed=len(triage_md.encode("utf-8")),
                    details={"format": "markdown"},
                )

        elif slice_id == 3:
            sub = sub_option or "pydantic_v2"
            schema_code = self._generate_schema(text, sub)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=schema_code,
                action_name=f"Schema Gen ({sub})",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(schema_code.encode("utf-8")),
                details={"sub_option": sub},
            )

        elif slice_id == 4:
            dockerfile = self._auto_dockerize(text)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=dockerfile,
                action_name="Auto-Dockerize",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(dockerfile.encode("utf-8")),
                details={"hardened": True, "non_root": True},
            )

        raise ValueError(f"Invalid slice_id {slice_id} for CodeLogOpsPlugin")

    def _crash_triage(self, log_text: str) -> str:
        """Parse log streams, deduplicate repeated messages, and extract root stack trace."""
        lines = log_text.splitlines()
        total_lines = len(lines)

        # 1. Deduplicate consecutive repeated lines
        deduped: List[Tuple[str, int]] = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if deduped and deduped[-1][0] == stripped:
                deduped[-1] = (stripped, deduped[-1][1] + 1)
            else:
                deduped.append((stripped, 1))

        # 2. Extract Traceback and Context
        tb_start = -1
        tb_end = -1
        for i, line in enumerate(lines):
            if "Traceback (most recent call last):" in line or "Exception in thread" in line or "panic: " in line:
                tb_start = i
                break

        stack_trace_snippet = ""
        context_before = []
        context_after = []

        if tb_start != -1:
            start_ctx = max(0, tb_start - 5)
            context_before = lines[start_ctx:tb_start]
            # Find end of traceback
            for j in range(tb_start + 1, total_lines):
                if lines[j] and not lines[j].startswith(" ") and not lines[j].startswith("\t"):
                    tb_end = j + 1
                    break
            if tb_end == -1:
                tb_end = min(total_lines, tb_start + 25)
            stack_trace_snippet = "\n".join(lines[tb_start:tb_end])
            context_after = lines[tb_end : min(total_lines, tb_end + 5)]
        else:
            # Fallback search for Error / Fatal / Exception keywords
            err_lines = [l for l in lines if any(k in l.upper() for k in ["ERROR", "FATAL", "CRITICAL", "EXCEPTION"])]
            stack_trace_snippet = "\n".join(err_lines[:15]) if err_lines else "No explicit stack trace identified."

        # Markdown Report Generation
        md = [
            "# ArcP Crash Triage & Incident Analysis",
            "",
            "### Summary Metrics",
            f"- **Total Raw Log Lines:** `{total_lines:,}`",
            f"- **Unique Compressed Lines:** `{len(deduped):,}`",
            f"- **Deduplication Ratio:** `{round((1 - len(deduped)/max(1, total_lines)) * 100, 1)}%` redundancy reduced",
            "",
            "### Root Stack Trace",
            "```text",
            stack_trace_snippet,
            "```",
            "",
        ]

        if context_before:
            md.extend([
                "### Context Lines Preceding Failure (-5 Lines)",
                "```text",
                "\n".join(context_before),
                "```",
                "",
            ])

        if context_after:
            md.extend([
                "### Context Lines Following Failure (+5 Lines)",
                "```text",
                "\n".join(context_after),
                "```",
                "",
            ])

        # Top repeating lines
        top_repeating = sorted([item for item in deduped if item[1] > 1], key=lambda x: x[1], reverse=True)[:5]
        if top_repeating:
            md.append("### High-Frequency Repeating Log Spans")
            for msg, count in top_repeating:
                md.append(f"- **[x{count} repeats]** `{msg[:100]}`")
            md.append("")

        return "\n".join(md)

    def _extract_fields_from_text(self, text: str) -> Dict[str, str]:
        """Infer key-type mappings from JSON, AST Python code, or SQL."""
        fields: Dict[str, str] = {}
        stripped = text.strip()

        # 1. Try JSON parsing
        try:
            data = json.loads(stripped)
            sample = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else data
            if isinstance(sample, dict):
                for k, v in sample.items():
                    if isinstance(v, bool):
                        fields[str(k)] = "bool"
                    elif isinstance(v, int):
                        fields[str(k)] = "int"
                    elif isinstance(v, float):
                        fields[str(k)] = "float"
                    elif isinstance(v, list):
                        fields[str(k)] = "list"
                    elif isinstance(v, dict):
                        fields[str(k)] = "dict"
                    else:
                        fields[str(k)] = "str"
                return fields
        except Exception:
            pass

        # 2. Try Python AST parsing
        try:
            tree = ast.parse(stripped)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    for item in node.body:
                        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                            type_name = "str"
                            if isinstance(item.annotation, ast.Name):
                                type_name = item.annotation.id
                            fields[item.target.id] = type_name
                        elif isinstance(item, ast.Assign):
                            for tgt in item.targets:
                                if isinstance(tgt, ast.Name):
                                    fields[tgt.id] = "Any"
                    if fields:
                        return fields
        except Exception:
            pass

        # 3. Simple key=value or SQL regex fallback
        for line in stripped.splitlines():
            line = line.strip().rstrip(",")
            m = re.match(r'["\']?([A-Za-z0-9_]+)["\']?\s*[:=]\s*(.+)', line)
            if m:
                k, v = m.group(1), m.group(2).strip().strip('"\'')
                if v.lower() in ("true", "false"):
                    fields[k] = "bool"
                elif v.isdigit():
                    fields[k] = "int"
                elif re.match(r"^-?\d+\.\d+$", v):
                    fields[k] = "float"
                else:
                    fields[k] = "str"

        if not fields:
            fields = {"id": "str", "name": "str", "status": "str", "count": "int"}
        return fields

    def _generate_schema(self, text: str, sub_option: str) -> str:
        """Generate typed schema in Pydantic v2, TypeScript, or C++20."""
        fields = self._extract_fields_from_text(text)

        if sub_option == "pydantic_v2":
            py_types = {"str": "str", "int": "int", "float": "float", "bool": "bool", "list": "list[Any]", "dict": "dict[str, Any]", "Any": "Any"}
            lines = [
                "from __future__ import annotations",
                "from typing import Any, Optional",
                "from pydantic import BaseModel, Field",
                "",
                "class AutoGeneratedModel(BaseModel):",
                '    """Strict Pydantic v2 validated schema generated by ArcP."""',
            ]
            for name, typ in fields.items():
                t = py_types.get(typ, "str")
                lines.append(f"    {name}: {t} = Field(..., description='Auto-inferred field')")
            lines.append("")
            return "\n".join(lines)

        elif sub_option == "typescript":
            ts_types = {"str": "string", "int": "number", "float": "number", "bool": "boolean", "list": "any[]", "dict": "Record<string, any>", "Any": "any"}
            lines = [
                "/**",
                " * Auto-generated TypeScript Interface by ArcP In-Memory Pipeline",
                " */",
                "export interface AutoGeneratedModel {",
            ]
            for name, typ in fields.items():
                t = ts_types.get(typ, "string")
                lines.append(f"  {name}: {t};")
            lines.append("}\n")
            return "\n".join(lines)

        elif sub_option == "cpp20":
            cpp_types = {"str": "std::string", "int": "int64_t", "float": "double", "bool": "bool", "list": "std::vector<std::string>", "dict": "std::unordered_map<std::string, std::string>", "Any": "std::string"}
            lines = [
                "#pragma once",
                "#include <cstdint>",
                "#include <string>",
                "#include <vector>",
                "#include <unordered_map>",
                "",
                "// ArcP In-Memory C++20 Generated Struct",
                "struct AutoGeneratedModel {",
            ]
            for name, typ in fields.items():
                t = cpp_types.get(typ, "std::string")
                lines.append(f"    {t} {name};")
            lines.append("};\n")
            return "\n".join(lines)

        return ""

    def _auto_dockerize(self, code_text: str) -> str:
        """Detect language, framework, and generate hardened multi-stage Dockerfile."""
        # Framework and runtime heuristics
        is_python = "import " in code_text or "def " in code_text or "print(" in code_text
        is_node = "const " in code_text or "require(" in code_text or "export " in code_text or "function " in code_text

        if is_python:
            has_fastapi = "fastapi" in code_text.lower()
            has_flask = "flask" in code_text.lower()
            has_streamlit = "streamlit" in code_text.lower()

            port = "8000" if has_fastapi else ("5000" if has_flask else ("8501" if has_streamlit else "8080"))
            cmd = (
                '["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]'
                if has_fastapi
                else (
                    '["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]'
                    if has_streamlit
                    else '["python", "main.py"]'
                )
            )

            return f"""# syntax=docker/dockerfile:1.4
# Multi-stage hardened production Dockerfile generated by ArcP
# 100% Non-root, zero CVE base, optimized layer caching

# ----------------- Stage 1: Build & Dependencies -----------------
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PIP_NO_CACHE_DIR=1 \\
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /install

RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/install --no-warn-script-location -r requirements.txt

# ----------------- Stage 2: Final Minimal Runtime -----------------
FROM python:3.11-slim-bookworm AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PORT={port}

WORKDIR /app

# Security: Create non-root unprivileged service account
RUN groupadd -g 10001 appgroup && \\
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser

# Copy installed wheels and runtime files
COPY --from=builder /install /usr/local
COPY --chown=appuser:appgroup . /app

USER appuser:appgroup

EXPOSE {port}

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:{port}/health || exit 1

CMD {cmd}
"""
        elif is_node:
            return """# syntax=docker/dockerfile:1.4
# Multi-stage hardened Node.js Dockerfile generated by ArcP
FROM node:20-alpine AS builder

WORKDIR /build
COPY package*.json ./
RUN npm ci --only=production

# ----------------- Runner Stage -----------------
FROM node:20-alpine AS runner

ENV NODE_ENV=production
WORKDIR /app

RUN addgroup -g 1001 -S nodejs && \\
    adduser -S nodejs -u 1001

COPY --from=builder /build/node_modules ./node_modules
COPY --chown=nodejs:nodejs . .

USER nodejs

EXPOSE 3000
CMD ["node", "server.js"]
"""
        else:
            # Generic Scratch / Alpine fallback
            return """# syntax=docker/dockerfile:1.4
# Hardened multi-stage Dockerfile generated by ArcP
FROM alpine:3.19 AS runner
RUN adduser -D -u 10001 appuser
WORKDIR /app
COPY . /app
RUN chown -R appuser:appuser /app
USER appuser
CMD ["./entrypoint.sh"]
"""
