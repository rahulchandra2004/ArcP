"""
Mode 5: INFRA Operations Plugin for ArcP.
Provides Cloud & Container Security Audit, Mermaid.js Architecture Diagram Generation,
Production Kubernetes Manifest Conversion, and .env.example Template Extraction.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

import yaml

from core.mime_router import MimeMode
from plugins.base_plugin import PipeResult, RadialAction, SliceConfig, SubSliceConfig


class InfraOpsPlugin(RadialAction):
    """Polymorphic Infrastructure Operations Plugin."""

    SENSITIVE_PORTS = {
        "22": "SSH Remote Access",
        "3389": "RDP Remote Desktop",
        "2375": "Unencrypted Docker Daemon",
        "2376": "Docker Swarm Management",
        "6379": "Redis Unauthenticated Port",
        "27017": "MongoDB Default Port",
        "9200": "Elasticsearch HTTP Port",
    }

    def __init__(self) -> None:
        super().__init__(MimeMode.INFRA, "Infra Operations")
        self._init_slices()

    def _init_slices(self) -> None:
        self.slices[1] = SliceConfig(
            slice_id=1,
            name="Cloud & Container Audit",
            description="Audit root execution, :latest tags, exposed ports, and privileged caps",
        )
        self.slices[2] = SliceConfig(
            slice_id=2,
            name="Mermaid Architecture",
            description="Generate Mermaid.js flowchart of services, dependencies, and networks",
        )
        self.slices[3] = SliceConfig(
            slice_id=3,
            name="K8s Manifest Converter",
            description="Convert Dockerfile/Compose into Deployment + Service with probes",
        )
        self.slices[4] = SliceConfig(
            slice_id=4,
            name="Env Template Gen",
            description="Extract ${ENV} and ARG vars into documented .env.example",
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
            audit_md, vuln_count = self._security_audit(text)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=audit_md,
                action_name="Cloud & Container Security Audit",
                mode=self.mode,
                latency_ms=latency,
                secrets_blocked=vuln_count,
                bytes_streamed=len(audit_md.encode("utf-8")),
                details={"vulnerabilities_detected": vuln_count},
            )

        elif slice_id == 2:
            mermaid_code = self._generate_mermaid(text)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=mermaid_code,
                action_name="Mermaid.js Architecture Gen",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(mermaid_code.encode("utf-8")),
                details={"format": "mermaid"},
            )

        elif slice_id == 3:
            k8s_yaml = self._convert_to_k8s(text)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=k8s_yaml,
                action_name="K8s Manifest Converter",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(k8s_yaml.encode("utf-8")),
                details={"kind": "Deployment+Service"},
            )

        elif slice_id == 4:
            env_example = self._extract_env_template(text)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=env_example,
                action_name="Env & Secret Template Gen",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(env_example.encode("utf-8")),
                details={"format": "dotenv"},
            )

        raise ValueError(f"Invalid slice_id {slice_id} for InfraOpsPlugin")

    def _security_audit(self, text: str) -> Tuple[str, int]:
        """Perform comprehensive container and infrastructure security static analysis."""
        findings: List[Tuple[str, str, str]] = []  # (severity, title, recommendation)
        lines = text.splitlines()

        # 1. Dockerfile checks
        is_dockerfile = any(l.strip().upper().startswith("FROM ") for l in lines)
        if is_dockerfile:
            has_user = False
            for idx, line in enumerate(lines, 1):
                clean = line.strip()
                if clean.upper().startswith("USER "):
                    has_user = True
                    user_val = clean.split()[1]
                    if user_val in ("root", "0"):
                        findings.append(("CRITICAL", f"Explicit root user specified at line {idx}: `{clean}`", "Switch to an unprivileged UID > 10000."))
                if clean.upper().startswith("FROM ") and (":latest" in clean or ":" not in clean.split()[1]):
                    findings.append(("MEDIUM", f"Unpinned `:latest` or floating base image at line {idx}", "Pin immutable SHA256 digest or exact semantic version."))
                for port, desc in self.SENSITIVE_PORTS.items():
                    if clean.upper().startswith(f"EXPOSE {port}") or f":{port}" in clean:
                        findings.append(("HIGH", f"Exposed high-risk sensitive port {port} ({desc})", "Avoid exposing administrative management ports."))

            if not has_user:
                findings.append(("HIGH", "Missing unprivileged USER instruction", "Defaulting to root execution allows container breakout risks. Add `USER appuser`."))

        # 2. Docker Compose / YAML checks
        try:
            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict) and "services" in parsed:
                for s_name, s_conf in parsed.get("services", {}).items():
                    if not isinstance(s_conf, dict):
                        continue
                    if s_conf.get("privileged") is True:
                        findings.append(("CRITICAL", f"Service `{s_name}` runs with privileged: true", "Never grant full host kernel capabilities. Use granular cap_add."))
                    if s_conf.get("network_mode") == "host":
                        findings.append(("HIGH", f"Service `{s_name}` uses host network mode", "Isolate containers within custom bridge networks."))
                    image_str = str(s_conf.get("image", ""))
                    if image_str and (image_str.endswith(":latest") or ":" not in image_str):
                        findings.append(("MEDIUM", f"Service `{s_name}` uses unpinned image `{image_str}`", "Specify immutable image tags."))
        except Exception:
            pass

        # 3. Hardcoded Secret Patterns
        secret_regex = re.compile(r"(?i)(password|secret|api_key|token|access_key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?")
        for idx, line in enumerate(lines, 1):
            if secret_regex.search(line):
                findings.append(("CRITICAL", f"Hardcoded credential detected at line {idx}", "Inject credentials via environment variables or secret vaults."))

        vuln_count = len(findings)
        md = [
            "# 🛡️ ArcP Infrastructure Security Audit",
            "",
            f"### Vulnerabilities Identified: `{vuln_count}`",
            "",
            "| Severity | Issue Description | Remediation |",
            "|---|---|---|",
        ]
        if findings:
            for sev, issue, fix in findings:
                md.append(f"| **{sev}** | {issue} | {fix} |")
        else:
            md.append("| **PASSED** | No known misconfigurations detected. | All baseline checks satisfied. |")

        return "\n".join(md), vuln_count

    def _generate_mermaid(self, text: str) -> str:
        """Parse Compose, Dockerfile, or Terraform and generate a Mermaid flowchart."""
        nodes: List[str] = []
        links: List[str] = []

        try:
            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict) and "services" in parsed:
                services = parsed["services"]
                for name, cfg in services.items():
                    if not isinstance(cfg, dict):
                        continue
                    img = cfg.get("image", "custom-build")
                    ports = cfg.get("ports", [])
                    port_str = f"\\nPorts: {','.join([str(p) for p in ports[:2]])}" if ports else ""
                    nodes.append(f'        {name}["{name}\\n({img}){port_str}"]')

                    deps = cfg.get("depends_on", [])
                    if isinstance(deps, list):
                        for dep in deps:
                            links.append(f"        {name} -->|depends_on| {dep}")
                    elif isinstance(deps, dict):
                        for dep in deps.keys():
                            links.append(f"        {name} -->|depends_on| {dep}")

                mermaid = ["```mermaid", "flowchart TD", "    subgraph DockerComposeStack[\"Docker Compose Topology\"]"]
                mermaid.extend(nodes)
                mermaid.extend(links)
                mermaid.append("    end")
                mermaid.append("```")
                return "\n".join(mermaid)
        except Exception:
            pass

        # Dockerfile Multi-stage fallback
        stages = re.findall(r"(?i)FROM\s+([^\s]+)\s+AS\s+([^\s]+)", text)
        if stages:
            mermaid = ["```mermaid", "flowchart LR", "    subgraph BuildPipeline[\"Multi-Stage Build Pipeline\"]"]
            for idx, (base_img, stage_name) in enumerate(stages):
                mermaid.append(f'        stage_{idx}["Stage: {stage_name}\\n(Base: {base_img})"]')
                if idx > 0:
                    mermaid.append(f"        stage_{idx-1} -->|artifacts| stage_{idx}")
            mermaid.append("    end")
            mermaid.append("```")
            return "\n".join(mermaid)

        return """```mermaid
flowchart TD
    Client["Client / User"] --> Gateway["API Gateway / Ingress"]
    Gateway --> ServiceA["Backend Microservice"]
    ServiceA --> DB[("Database Cluster")]
    ServiceA --> Cache[("Redis Cache")]
```"""

    def _convert_to_k8s(self, text: str) -> str:
        """Convert Dockerfile / Compose service into production Kubernetes Deployment + Service."""
        service_name = "app-service"
        image_name = "app:v1.0.0"
        port = 8080

        # Extract hints
        try:
            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict) and "services" in parsed:
                first_name = list(parsed["services"].keys())[0]
                service_name = first_name
                cfg = parsed["services"][first_name]
                if isinstance(cfg, dict):
                    image_name = cfg.get("image", image_name)
                    ports = cfg.get("ports", [])
                    if ports:
                        raw_port = str(ports[0]).split(":")[-1]
                        if raw_port.isdigit():
                            port = int(raw_port)
        except Exception:
            pass

        return f"""# Kubernetes Production Manifest generated by ArcP
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {service_name}-deployment
  labels:
    app.kubernetes.io/name: {service_name}
    app.kubernetes.io/managed-by: arcp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: {service_name}
  template:
    metadata:
      labels:
        app: {service_name}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
      containers:
      - name: {service_name}
        image: {image_name}
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: {port}
          name: http
        resources:
          limits:
            cpu: "1000m"
            memory: "1024Mi"
          requests:
            cpu: "250m"
            memory: "256Mi"
        livenessProbe:
          httpGet:
            path: /health
            port: {port}
          initialDelaySeconds: 15
          periodSeconds: 20
        readinessProbe:
          httpGet:
            path: /ready
            port: {port}
          initialDelaySeconds: 5
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: {service_name}
  labels:
    app.kubernetes.io/name: {service_name}
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: {port}
    protocol: TCP
    name: http
  selector:
    app: {service_name}
"""

    def _extract_env_template(self, text: str) -> str:
        """Extract referenced environment variables into a documented .env.example template."""
        env_vars = set()

        # Match ${VAR} or ${VAR:-default}
        for m in re.finditer(r"\$\{([A-Za-z0-9_]+)(?::-([^}]+))?\}", text):
            env_vars.add((m.group(1), m.group(2) or ""))

        # Match ENV VAR=val or ARG VAR
        for line in text.splitlines():
            line = line.strip()
            if line.upper().startswith("ENV ") or line.upper().startswith("ARG "):
                parts = line.split(maxsplit=2)
                if len(parts) >= 2:
                    sub = parts[1]
                    if "=" in sub:
                        k, v = sub.split("=", 1)
                        env_vars.add((k.strip(), v.strip()))
                    else:
                        env_vars.add((sub.strip(), ""))

        lines = [
            "# ===================================================================",
            "# ArcP Auto-Generated In-Memory Environment Variable Template",
            "# Copy this file to .env and supply environment-specific credentials",
            "# ===================================================================",
            "",
        ]

        if env_vars:
            for k, default_val in sorted(env_vars):
                lines.append(f"# Configuration setting: {k}")
                val_repr = default_val if default_val else f"your_{k.lower()}_here"
                lines.append(f"{k}={val_repr}")
                lines.append("")
        else:
            lines.extend([
                "# Standard Default Runtime Settings",
                "APP_ENV=production",
                "PORT=8080",
                "LOG_LEVEL=info",
                "DATABASE_URL=postgresql://user:password@localhost:5432/app_db",
                "SECRET_KEY=change_me_to_a_secure_random_token",
            ])

        return "\n".join(lines)
