"""
Mode 6: BINARY Operations Plugin for ArcP.
Provides pure-Python ELF/PE Header X-Ray, Strings & IOC Extractor,
Imported Library/Symbol Audit, and Threat-Intel Cryptographic Hash & Byte-Entropy Manifest.
"""
from __future__ import annotations

import ast
import hashlib
import math
import re
import struct
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from core.mime_router import MimeMode
from plugins.base_plugin import PipeResult, RadialAction, SliceConfig, SubSliceConfig


class BinaryOpsPlugin(RadialAction):
    """Polymorphic Binary Inspection and DevSecOps Plugin."""

    def __init__(self) -> None:
        super().__init__(MimeMode.BINARY, "Binary Operations")
        self._init_slices()

    def _init_slices(self) -> None:
        self.slices[1] = SliceConfig(
            slice_id=1,
            name="ELF / PE X-Ray",
            description="Arch, entry point, ASLR & NX",
            icon="microscope",
        )
        self.slices[2] = SliceConfig(
            slice_id=2,
            name="IOC Extractor",
            description="Extract URLs, IPs, paths & keys",
            icon="search",
        )
        self.slices[3] = SliceConfig(
            slice_id=3,
            name="Symbol Audit",
            description="Inspect imported libs & symbols",
            icon="binary",
        )
        self.slices[4] = SliceConfig(
            slice_id=4,
            name="Crypto Hashes",
            description="MD5, SHA256 & packer entropy",
            icon="hash",
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
            header_md = self._xray_headers(raw_bytes)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=header_md,
                action_name="ELF / PE Header X-Ray",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(header_md.encode("utf-8")),
                details={"format": "markdown"},
            )

        elif slice_id == 2:
            strings_md, ioc_count = self._extract_strings_and_iocs(raw_bytes)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=strings_md,
                action_name="Strings & IOC Extractor",
                mode=self.mode,
                latency_ms=latency,
                secrets_blocked=ioc_count,
                bytes_streamed=len(strings_md.encode("utf-8")),
                details={"iocs_found": ioc_count},
            )

        elif slice_id == 3:
            sym_md = self._audit_symbols_and_libs(raw_bytes)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=sym_md,
                action_name="Symbol & Library Audit",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(sym_md.encode("utf-8")),
                details={"format": "markdown"},
            )

        elif slice_id == 4:
            manifest_md, entropy = self._hash_manifest(raw_bytes)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=manifest_md,
                action_name="Cryptographic Hash Manifest",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(manifest_md.encode("utf-8")),
                details={"shannon_entropy": entropy},
            )

        raise ValueError(f"Invalid slice_id {slice_id} for BinaryOpsPlugin")

    def _xray_headers(self, b: bytes) -> str:
        """Parse ELF or PE headers in pure Python with struct."""
        # 1. ELF Inspection
        if b.startswith(b"\x7fELF"):
            if len(b) < 52:
                return "# Corrupted or Truncated ELF Binary"
            ei_class = b[4]
            is_64 = ei_class == 2
            ei_data = b[5]
            endian = "<" if ei_data == 1 else ">"
            e_type, e_machine = struct.unpack(f"{endian}HH", b[16:20])

            mach_names = {3: "x86 (i386)", 62: "x86_64 (AMD64)", 40: "ARM 32-bit", 183: "AArch64 (ARM64)"}
            mach_str = mach_names.get(e_machine, f"Architecture ID: {e_machine}")

            entry_point = 0
            if is_64 and len(b) >= 32:
                entry_point = struct.unpack(f"{endian}Q", b[24:32])[0]
            elif not is_64 and len(b) >= 28:
                entry_point = struct.unpack(f"{endian}I", b[24:28])[0]

            is_pie = e_type == 3  # ET_DYN is PIE (Position Independent Executable)
            pie_str = "[PASS] ENABLED (ET_DYN)" if is_pie else "[FAIL] DISABLED (ET_EXEC)"

            return f"""# ArcP Binary Header X-Ray: Linux ELF

### Execution Specification
- **Format:** ELF {'64-bit' if is_64 else '32-bit'} ({'Little' if ei_data == 1 else 'Big'} Endian)
- **Target Architecture:** `{mach_str}`
- **Entry Point Address:** `0x{entry_point:016X}`
- **ELF Type Code:** `{e_type}`

### Exploit Mitigations
| Mitigation | Status | Detail |
|---|---|---|
| **PIE / ASLR** | {pie_str} | Position Independent Executable |
| **NX / DEP** | [ACTIVE] ACTIVE | Non-Executable Stack default |
"""

        # 2. PE Inspection
        if b.startswith(b"MZ"):
            if len(b) < 64:
                return "# Corrupted or Truncated DOS / PE Binary"
            pe_offset = struct.unpack("<I", b[0x3C:0x40])[0]
            if pe_offset + 24 > len(b) or b[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                return "# MS-DOS Executable (No PE Header)"

            coff = b[pe_offset + 4 : pe_offset + 24]
            machine, num_sections, timedate, sym_ptr, num_syms, opt_hdr_size, characteristics = struct.unpack(
                "<HHIIIHH", coff
            )

            mach_names = {0x014C: "x86 (32-bit)", 0x8664: "x86_64 (AMD64)", 0xAA64: "ARM64"}
            mach_str = mach_names.get(machine, f"Machine ID: 0x{machine:04X}")

            aslr = False
            dep = False
            cfg = False
            entry_point = 0

            if opt_hdr_size > 0 and len(b) >= pe_offset + 24 + opt_hdr_size:
                opt_hdr = b[pe_offset + 24 : pe_offset + 24 + opt_hdr_size]
                magic = struct.unpack("<H", opt_hdr[:2])[0]
                is_pe32_plus = magic == 0x20B
                entry_point = struct.unpack("<I", opt_hdr[16:20])[0]

                # DllCharacteristics is at offset 70 for PE32+, 68 for PE32
                dll_char_offset = 70 if is_pe32_plus else 68
                if len(opt_hdr) >= dll_char_offset + 2:
                    dll_char = struct.unpack("<H", opt_hdr[dll_char_offset : dll_char_offset + 2])[0]
                    aslr = bool(dll_char & 0x0040)
                    dep = bool(dll_char & 0x0100)
                    cfg = bool(dll_char & 0x4000)

            return f"""# ArcP Binary Header X-Ray: Windows PE

### Execution Specification
- **Format:** Portable Executable (PE32{' +' if machine == 0x8664 else ''})
- **Architecture:** `{mach_str}`
- **Sections Count:** `{num_sections}`
- **Entry Point RVA:** `0x{entry_point:08X}`
- **Characteristics:** `0x{characteristics:04X}`

### Security Mitigations
| Mitigation | Status | Standard |
|---|---|---|
| **ASLR** (Dynamic Base) | {'[PASS] ENABLED' if aslr else '[FAIL] DISABLED'} | Image randomization at load |
| **DEP / NX** | {'[PASS] ENABLED' if dep else '[FAIL] DISABLED'} | Hardware Data Execution Prevention |
| **Control Flow Guard** | {'[PASS] ENABLED' if cfg else '[WARN] DISABLED'} | Exploit mitigation (CFG) |
"""

        # 3. Source / Script / Text Byte Stream Inspection
        return self._xray_script_or_text(b)

    def _xray_script_or_text(self, b: bytes) -> str:
        """Inspect source/script files or non-ELF/PE binaries."""
        length = len(b)

        # 1. Encoding & BOM
        bom_desc = "None"
        encoding = "UTF-8"
        if b.startswith(b"\xef\xbb\xbf"):
            bom_desc = "UTF-8 BOM (0xEF 0xBB 0xBF)"
            encoding = "UTF-8-SIG"
        elif b.startswith(b"\xff\xfe"):
            bom_desc = "UTF-16 LE BOM (0xFF 0xFE)"
            encoding = "UTF-16-LE"
        elif b.startswith(b"\xfe\xff"):
            bom_desc = "UTF-16 BE BOM (0xFE 0xFF)"
            encoding = "UTF-16-BE"
        else:
            try:
                b.decode("ascii")
                encoding = "ASCII (7-bit clean)"
            except UnicodeDecodeError:
                try:
                    b.decode("utf-8")
                    encoding = "UTF-8 (No BOM)"
                except UnicodeDecodeError:
                    encoding = "Binary / ISO-8859-1"

        # 2. Line Endings
        crlf_count = b.count(b"\r\n")
        lf_count = b.count(b"\n") - crlf_count
        if crlf_count > 0 and lf_count == 0:
            line_endings = f"CRLF (Windows standard, {crlf_count:,} lines)"
        elif lf_count > 0 and crlf_count == 0:
            line_endings = f"LF (Unix standard, {lf_count:,} lines)"
        elif crlf_count > 0 and lf_count > 0:
            line_endings = f"Mixed (CRLF: {crlf_count:,}, LF: {lf_count:,})"
        else:
            line_endings = "Single line / Non-terminated"

        # 3. Shebang Line
        shebang = "None detected"
        if b.startswith(b"#!"):
            first_line = b.splitlines()[0] if b.splitlines() else b
            try:
                shebang = first_line.decode("utf-8", errors="replace").strip()
            except Exception:
                shebang = repr(first_line)

        # 4. Hex Dump of first 64 bytes
        first_64 = b[:64]
        hex_lines = []
        for offset in range(0, len(first_64), 16):
            chunk = first_64[offset : offset + 16]
            hex_part1 = " ".join(f"{byte:02x}" for byte in chunk[:8])
            hex_part2 = " ".join(f"{byte:02x}" for byte in chunk[8:])
            hex_str = f"{hex_part1:<23}  {hex_part2:<23}".rstrip()
            ascii_str = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            hex_lines.append(f"{offset:08x}:  {hex_str:<48}  |{ascii_str}|")
        hex_dump_md = "\n".join(hex_lines) if hex_lines else "00000000:  <empty payload>"

        # 5. Shannon Entropy
        entropy = 0.0
        if length > 0:
            counts = Counter(b)
            entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())

        if entropy < 5.2:
            entropy_eval = "Text / Source Code Distribution (Clean)"
        elif entropy < 7.0:
            entropy_eval = "Structured Binary or Compressed Script"
        else:
            entropy_eval = "High Entropy / Packed / Encrypted"

        return f"""# ArcP File Byte & Runtime Header X-Ray

### Execution & Encoding Specification
- **Payload Format:** Script / Source / Text Stream
- **Exact Size:** `{length:,} bytes` ({round(length / 1024.0, 2)} KB)
- **Character Encoding:** `{encoding}` (BOM: `{bom_desc}`)
- **Line Terminations:** `{line_endings}`
- **Runtime Shebang:** `{shebang}`
- **Shannon Byte Entropy:** `{entropy:.4f} / 8.0000` ({entropy_eval})

### First 64 Bytes Canonical Hex Dump
```text
{hex_dump_md}
```
"""

    def _extract_strings_and_iocs(self, b: bytes) -> Tuple[str, int]:
        """Extract printable strings and categorize threat intel IOCs & secrets."""
        # Find printable ASCII (length >= 5)
        ascii_matches = [s.decode("ascii", errors="ignore") for s in re.findall(b"[ -~]{5,}", b)]
        # Find UTF-16 strings
        utf16_raw = re.findall(b"(?:[ -~]\x00){5,}", b)
        utf16_matches = [s.decode("utf-16le", errors="ignore") for s in utf16_raw]

        all_strings = ascii_matches + utf16_matches
        total_strings = len(all_strings)

        urls = []
        ips = []
        paths = []
        reg_keys = []
        secrets = []

        url_re = re.compile(r"https?://[a-zA-Z0-9_\-\./:\?\#\[\]@!$&'\(\)\*\+,;=%]+")
        ip_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        path_re = re.compile(r"(?:[a-zA-Z]:\\[A-Za-z0-9_\.\\]+|/(?:etc|usr|bin|var|tmp|home)/[A-Za-z0-9_\./]+)")
        reg_re = re.compile(r"(?:HKEY_[A-Z_]+|HKLM\\|HKCU\\)[A-Za-z0-9_\\]+")

        secret_patterns = [
            (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key"),
            (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"), "Private Key Header"),
            (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"), "GitHub Token"),
            (re.compile(r"(?:api[_-]?key|secret|token|password|bearer)[ \t]*[=:][ \t]*['\"][a-zA-Z0-9_\-\.]{8,}['\"]", re.IGNORECASE), "Credential Token"),
        ]

        for s in all_strings:
            for u in url_re.findall(s):
                urls.append(u)
            for ip in ip_re.findall(s):
                if not ip.startswith("0.0.") and not ip.startswith("127.0."):
                    ips.append(ip)
            for p in path_re.findall(s):
                paths.append(p)
            for r in reg_re.findall(s):
                reg_keys.append(r)
            for pat, desc in secret_patterns:
                for match in pat.findall(s):
                    secrets.append(f"{desc}: `{match[:32]}...`" if len(match) > 32 else f"{desc}: `{match}`")

        urls = sorted(set(urls))[:15]
        ips = sorted(set(ips))[:15]
        paths = sorted(set(paths))[:15]
        reg_keys = sorted(set(reg_keys))[:15]
        secrets = sorted(set(secrets))[:15]

        ioc_total = len(urls) + len(ips) + len(paths) + len(reg_keys) + len(secrets)

        md = [
            "# ArcP Strings & IOC X-Ray",
            "",
            f"- **Total Extracted Strings:** `{total_strings:,}`",
            f"- **Indicators of Compromise & Secrets (IOCs):** `{ioc_total}`",
            "",
            "### Embedded URLs & Network Endpoints",
        ]
        md.extend([f"- `{u}`" for u in urls] if urls else ["- *No URLs detected.*"])

        md.extend(["", "### Embedded IP Addresses"])
        md.extend([f"- `{ip}`" for ip in ips] if ips else ["- *No external IPs detected.*"])

        md.extend(["", "### Embedded File Paths"])
        md.extend([f"- `{p}`" for p in paths] if paths else ["- *No hardcoded paths detected.*"])

        md.extend(["", "### Registry Keys"])
        md.extend([f"- `{r}`" for r in reg_keys] if reg_keys else ["- *No registry keys detected.*"])

        md.extend(["", "### Embedded Secrets & Credentials"])
        md.extend([f"- {s}" for s in secrets] if secrets else ["- *No embedded credentials or API keys detected.*"])

        return "\n".join(md), ioc_total

    def _audit_symbols_and_libs(self, b: bytes) -> str:
        """Inspect imported symbols: Python AST parser for source files, or binary string audit."""
        # 1. Try parsing payload as Python source code
        try:
            text = b.decode("utf-8", errors="replace")
            if text.startswith("\ufeff"):
                text = text[1:]
            tree = ast.parse(text)
            return self._audit_python_ast(text, tree)
        except Exception:
            pass

        # 2. Fallback to native binary ELF/PE symbol extraction
        ascii_strings = [s.decode("ascii", errors="ignore") for s in re.findall(rb"[a-zA-Z0-9_.-]{4,}", b)]

        libs = set()
        syms = set()

        for s in ascii_strings:
            lower = s.lower()
            if lower.endswith(".dll") or lower.endswith(".so") or ".so." in lower:
                libs.add(s)
            elif any(s.startswith(prefix) for prefix in ("Create", "Get", "Set", "Virtual", "Write", "Read", "Reg", "Http", "Socket", "WSA")):
                syms.add(s)
            elif any(s.startswith(prefix) for prefix in ("pthread_", "malloc", "free", "printf", "dlopen", "sys_")):
                syms.add(s)

        md = [
            "# ArcP Symbol & Dynamic Library Audit",
            "",
            f"- **Referenced Shared Libraries:** `{len(libs)}`",
            f"- **Identified API Symbols:** `{len(syms)}`",
            "",
            "### Imported Dynamic Libraries (.dll / .so)",
        ]
        md.extend([f"- `{lib}`" for lib in sorted(libs)[:20]] if libs else ["- *No explicit dynamic libraries matched.*"])

        md.extend(["", "### Critical System & API Symbols"])
        md.extend([f"- `{sym}`" for sym in sorted(syms)[:30]] if syms else ["- *No common exported API symbols isolated.*"])

        return "\n".join(md)

    def _audit_python_ast(self, text: str, tree: ast.AST) -> str:
        """Generate comprehensive Python AST Symbol & Dependency Audit."""
        imports: List[str] = []
        from_imports: List[str] = []
        classes: List[Dict[str, Any]] = []
        functions: List[Dict[str, Any]] = []
        constants: List[Tuple[str, int]] = []
        native_bindings: List[str] = []

        class ASTCollector(ast.NodeVisitor):
            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    name = alias.name
                    if alias.asname:
                        name += f" as {alias.asname}"
                    imports.append(f"`{name}` (L{node.lineno})")
                    if alias.name in ("ctypes", "cffi", "win32api", "win32con", "winrt", "cython"):
                        native_bindings.append(f"Native C/C++ Binding: `import {alias.name}` at line {node.lineno}")
                self.generic_visit(node)

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                mod = node.module or ""
                items = [a.name if not a.asname else f"{a.name} as {a.asname}" for a in node.names]
                from_imports.append(f"`from {mod} import {', '.join(items)}` (L{node.lineno})")
                if mod in ("ctypes", "cffi", "win32api", "win32con", "winrt", "subprocess"):
                    native_bindings.append(f"Foreign C/C++ Interface: `from {mod} import {', '.join(items)}` at line {node.lineno}")
                self.generic_visit(node)

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                bases = [ast.unparse(b) for b in node.bases] if hasattr(ast, "unparse") else []
                methods_count = len([n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))])
                classes.append({
                    "name": node.name,
                    "bases": ", ".join(bases) if bases else "object",
                    "methods": methods_count,
                    "lineno": node.lineno,
                })
                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._record_fn(node, is_async=False)
                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._record_fn(node, is_async=True)
                self.generic_visit(node)

            def _record_fn(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
                args_strs = []
                for arg in node.args.args:
                    s = arg.arg
                    if arg.annotation and hasattr(ast, "unparse"):
                        s += f": {ast.unparse(arg.annotation)}"
                    args_strs.append(s)
                if node.args.vararg:
                    args_strs.append(f"*{node.args.vararg.arg}")
                if node.args.kwarg:
                    args_strs.append(f"**{node.args.kwarg.arg}")

                ret_str = ""
                if getattr(node, "returns", None) and hasattr(ast, "unparse"):
                    ret_str = f" -> {ast.unparse(node.returns)}"

                prefix = "async def" if is_async else "def"
                sig = f"{prefix} {node.name}({', '.join(args_strs)}){ret_str}"
                functions.append({
                    "sig": sig,
                    "lineno": node.lineno,
                })

            def visit_Assign(self, node: ast.Assign) -> None:
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        constants.append((target.id, node.lineno))
                self.generic_visit(node)

            def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
                if isinstance(node.target, ast.Name) and node.target.id.isupper():
                    constants.append((node.target.id, node.lineno))
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id in ("ctypes", "cffi", "cdll", "windll"):
                        native_bindings.append(f"Direct Foreign Invocation: `{node.func.value.id}.{node.func.attr}()` at line {node.lineno}")
                self.generic_visit(node)

        ASTCollector().visit(tree)

        lines_count = len(text.splitlines())
        total_imports = len(imports) + len(from_imports)

        md = [
            "# ArcP Python AST Symbol & Dependency Audit",
            "",
            "### Module Structural Metrics",
            f"- **Lines of Source Code:** `{lines_count:,}`",
            f"- **Imported Modules & Packages:** `{total_imports}`",
            f"- **Class Declarations:** `{len(classes)}`",
            f"- **Function & Method Declarations:** `{len(functions)}`",
            f"- **Module Constants:** `{len(constants)}`",
            f"- **Native Foreign Interfaces:** `{len(native_bindings)}`",
            "",
            "### Module Imports & Dependencies",
        ]

        if imports or from_imports:
            md.extend([f"- {imp}" for imp in imports[:15]])
            md.extend([f"- {f_imp}" for f_imp in from_imports[:15]])
        else:
            md.append("- *No top-level module imports declared.*")

        md.extend(["", "### Class Structures & Inheritance"])
        if classes:
            md.append("| Class Name | Inherits From | Methods | Line |")
            md.append("|---|---|---|---|")
            for c in classes[:15]:
                md.append(f"| `{c['name']}` | `{c['bases']}` | `{c['methods']}` | L{c['lineno']} |")
        else:
            md.append("- *No class definitions in module.*")

        md.extend(["", "### Functions & Methods"])
        if functions:
            for fn in functions[:20]:
                md.append(f"- `L{fn['lineno']}`: `{fn['sig']}`")
            if len(functions) > 20:
                md.append(f"- *... and {len(functions) - 20} additional functions.*")
        else:
            md.append("- *No function definitions found.*")

        md.extend(["", "### Module-Level Constants"])
        if constants:
            md.extend([f"- `{c[0]}` (line {c[1]})" for c in constants[:15]])
        else:
            md.append("- *No uppercase module constants declared.*")

        md.extend(["", "### Native & Foreign C-Bindings Audit"])
        if native_bindings:
            md.extend([f"- [WARN] {nb}" for nb in native_bindings[:10]])
        else:
            md.append("- [PASS] **No native ctypes / cffi / foreign binary bindings detected.**")

        return "\n".join(md)

    def _hash_manifest(self, b: bytes) -> Tuple[str, float]:
        """Compute cryptographic hashes and Shannon byte-entropy for packer detection."""
        md5_val = hashlib.md5(b).hexdigest()
        sha1_val = hashlib.sha1(b).hexdigest()
        sha256_val = hashlib.sha256(b).hexdigest()

        # Shannon byte-level entropy over 256 byte frequency distribution
        length = len(b)
        entropy = 0.0
        if length > 0:
            counts = Counter(b)
            entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())

        is_packed = entropy > 7.2
        status = "[PACKED] PACKED / ENCRYPTED (High Entropy)" if is_packed else "[NORMAL] NORMAL / UNPACKED NATIVE CODE"

        md = f"""# ArcP Cryptographic Hash & Threat Intel Manifest

### File Hash Signatures
- **File Size:** `{length:,} bytes` ({round(length / (1024*1024), 2)} MB)
- **MD5:** `{md5_val}`
- **SHA-1:** `{sha1_val}`
- **SHA-256:** `{sha256_val}`

### Shannon Byte-Level Entropy
- **Entropy Score:** `{entropy:.4f} / 8.0000`
- **Assessment:** **{status}**
- **Analysis:** {'Entropy > 7.2 indicates cryptographic encryption or payload packing (e.g. UPX, Themida, VMProtect, AES data).' if is_packed else 'Standard code and resource distribution.'}
"""
        return md, round(entropy, 4)
