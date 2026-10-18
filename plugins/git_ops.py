"""
Mode 7: GIT_PATCH Operations Plugin for ArcP.
Provides Instant Clipboard Diff, git apply Patch Bundler, Semantic Conventional Commit Generator,
and Pre-Commit DevSecOps Gatekeeper.
"""
from __future__ import annotations

import ast
import difflib
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from PyQt6.QtWidgets import QApplication

from core.mime_router import MimeMode
from core.token_vault import TokenVault
from plugins.base_plugin import PipeResult, RadialAction, SliceConfig, SubSliceConfig


class GitOpsPlugin(RadialAction):
    """Polymorphic Git and Patch Operations Plugin."""

    def __init__(self, token_vault: Optional[TokenVault] = None) -> None:
        super().__init__(MimeMode.GIT_PATCH, "Git & Patch Operations")
        self.vault = token_vault or TokenVault()
        self._init_slices()

    def _init_slices(self) -> None:
        self.slices[1] = SliceConfig(
            slice_id=1,
            name="Clipboard Diff",
            description="Unified diff vs clipboard text",
            icon="diff",
        )
        self.slices[2] = SliceConfig(
            slice_id=2,
            name="Patch Bundler",
            description="Git apply compatible .patch",
            icon="git_branch",
        )
        self.slices[3] = SliceConfig(
            slice_id=3,
            name="Semantic Commit",
            description="Conventional commit message",
            icon="commit",
        )
        self.slices[4] = SliceConfig(
            slice_id=4,
            name="Gatekeeper",
            description="Pre-commit verify & secret scrub",
            icon="lock",
        )

    def execute(
        self,
        payload: Any,
        slice_id: int,
        sub_option: Optional[str] = None,
    ) -> PipeResult:
        start_time = time.perf_counter()
        file_text = self.read_payload_text(payload)

        # Get system clipboard text
        app = QApplication.instance()
        cb = QApplication.clipboard() if app else None
        clip_text = cb.text() if cb else ""

        if slice_id == 1:
            diff_md = self._compute_clipboard_diff(file_text, clip_text)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=diff_md,
                action_name="Instant Clipboard Diff",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(diff_md.encode("utf-8")),
                details={"format": "markdown_diff"},
            )

        elif slice_id == 2:
            patch_content, adds, dels = self._bundle_patch(file_text, clip_text)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=patch_content,
                action_name="Patch Bundler",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(patch_content.encode("utf-8")),
                details={"insertions": adds, "deletions": dels},
            )

        elif slice_id == 3:
            commit_msg = self._generate_commit_message(file_text, clip_text)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=commit_msg,
                action_name="Semantic Commit Gen",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(commit_msg.encode("utf-8")),
                details={"standard": "conventional_commits"},
            )

        elif slice_id == 4:
            gate_md, passed, blocked_count = self._pre_commit_gatekeeper(file_text)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=gate_md,
                action_name="Pre-Commit Gatekeeper",
                mode=self.mode,
                latency_ms=latency,
                secrets_blocked=blocked_count,
                bytes_streamed=len(gate_md.encode("utf-8")),
                details={"passed": passed, "issues_flagged": blocked_count},
            )

        raise ValueError(f"Invalid slice_id {slice_id} for GitOpsPlugin")

    def _compute_clipboard_diff(self, file_text: str, clip_text: str) -> str:
        """Compute unified diff between dropped content and system clipboard."""
        file_lines = file_text.splitlines(keepends=True)
        clip_lines = clip_text.splitlines(keepends=True) if clip_text else []

        if not clip_lines:
            clip_lines = ["# (Empty Clipboard)\n"]

        diff = list(
            difflib.unified_diff(
                clip_lines,
                file_lines,
                fromfile="clipboard/baseline",
                tofile="current/target",
                n=3,
            )
        )

        diff_str = "".join(diff) if diff else "# No differences detected between dropped payload and clipboard."
        return f"# ArcP Instant Unified Diff\n\n```diff\n{diff_str}\n```"

    def _bundle_patch(self, file_text: str, clip_text: str) -> Tuple[str, int, int]:
        """Generate a valid git apply patch bundle with diffstat header."""
        file_lines = file_text.splitlines(keepends=True)
        clip_lines = clip_text.splitlines(keepends=True) if clip_text else []

        diff = list(
            difflib.unified_diff(
                clip_lines,
                file_lines,
                fromfile="a/payload.txt",
                tofile="b/payload.txt",
                n=3,
            )
        )

        adds = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
        dels = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))

        header = [
            "From: ArcP In-Memory Pipeline <arcp@local>",
            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}",
            "Subject: [PATCH] In-memory atomic changes bundle",
            "",
            "---",
            f" payload.txt | {adds + dels} {'+' * min(adds, 20)}{'-' * min(dels, 20)}",
            f" 1 file changed, {adds} insertions(+), {dels} deletions(-)",
            "",
            "diff --git a/payload.txt b/payload.txt",
        ]

        full_patch = "\n".join(header) + "\n" + "".join(diff)
        return full_patch, adds, dels

    def _generate_commit_message(self, file_text: str, clip_text: str) -> str:
        """Analyze code delta to synthesize a Conventional Commits message."""
        # Detect intent based on added/modified lines using word boundaries
        has_tests = bool(re.search(r"\b(test|tests|pytest|unittest)\b", file_text, re.IGNORECASE))
        has_docs = '"""' in file_text or "README" in file_text or bool(re.search(r"\b(doc|docs|documentation)\b", file_text, re.IGNORECASE))
        has_feat = any(w in file_text for w in ["def ", "class ", "function ", "interface ", "struct "])
        has_fix = bool(re.search(r"\b(fix|fixes|fixed|bug|bugs|patch|hotfix|resolve|resolved)\b", file_text, re.IGNORECASE))

        if has_tests:
            commit_type = "test"
            scope = "e2e"
            desc = "add comprehensive test coverage for pipeline workflows"
        elif has_feat:
            commit_type = "feat"
            scope = "core"
            desc = "implement atomic in-memory transform operations"
        elif has_fix:
            commit_type = "fix"
            scope = "pipeline"
            desc = "resolve edge-case exception handling in stream processor"
        elif has_docs:
            commit_type = "docs"
            scope = "spec"
            desc = "update documentation and architecture diagrams"
        else:
            commit_type = "refactor"
            scope = "runtime"
            desc = "optimize memory layout and zero-disk buffer flow"

        # Extract functions/classes defined
        items = re.findall(r"(?:def|class)\s+([A-Za-z0-9_]+)", file_text)[:4]
        bullets = [f"- Implement `{it}` logic" for it in items] or [
            "- Update internal state management",
            "- Ensure thread-safe zero-disk execution",
        ]

        msg = [
            f"{commit_type}({scope}): {desc}",
            "",
            *bullets,
            "",
            "Signed-off-by: ArcP Autonomous Pipeline <arcp@local>",
        ]
        return "\n".join(msg)

    def _pre_commit_gatekeeper(self, code_text: str) -> Tuple[str, bool, int]:
        """Run secret scrub check, AST syntax verification, and debug statement detection."""
        issues: List[Tuple[str, str, str]] = []  # (severity, title, detail)

        # 1. Secret scrub verification
        _, secrets_count = self.vault.scrub_and_store(code_text)
        if secrets_count > 0:
            issues.append(("CRITICAL", f"Detected {secrets_count} unmasked secret(s)/credential(s)", "Scrub secrets using TokenVault before committing."))

        # 2. Python AST syntax verification
        try:
            ast.parse(code_text)
        except SyntaxError as e:
            issues.append(("CRITICAL", f"Python SyntaxError at line {e.lineno}", str(e.msg)))
        except Exception:
            pass

        # 3. Debug statement detection
        debug_patterns = [
            (re.compile(r"\bprint\s*\("), "Python `print()` statement detected"),
            (re.compile(r"\bbreakpoint\s*\("), "Python `breakpoint()` debugger call"),
            (re.compile(r"\bpdb\.set_trace\s*\("), "Python `pdb.set_trace()` active"),
            (re.compile(r"\bconsole\.log\s*\("), "JavaScript `console.log()` statement"),
            (re.compile(r"\bdebugger\s*;"), "JavaScript `debugger;` statement"),
        ]

        for idx, line in enumerate(code_text.splitlines(), 1):
            for pat, desc in debug_patterns:
                if pat.search(line):
                    issues.append(("WARNING", f"{desc} at line {idx}", f"`{line.strip()[:60]}`"))

        passed = not any(sev == "CRITICAL" for sev, _, _ in issues)
        status_banner = "[PASSED] PRE-COMMIT PASSED" if passed else "[BLOCKED] PRE-COMMIT BLOCKED (CRITICAL ISSUES)"

        md = [
            "# ArcP Pre-Commit Gatekeeper Audit",
            "",
            f"### Status: **{status_banner}**",
            f"- **Total Security/Quality Findings:** `{len(issues)}`",
            "",
            "| Severity | Issue | Details |",
            "|---|---|---|",
        ]
        if issues:
            for sev, title, detail in issues:
                md.append(f"| **{sev}** | {title} | {detail} |")
        else:
            md.append("| **PASSED** | Zero syntax errors, secrets, or debug statements. | Ready to commit. |")

        return "\n".join(md), passed, len(issues)
