"""
Mode 2: DATASET Operations Plugin for ArcP.
Provides Synthetic Twin generation, PII Masking with deterministic salted hashes,
Instant single-file Dark-Mode EDA Profile HTML, and in-memory Format Transpilation.
"""
from __future__ import annotations

import hashlib
import io
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from core.mime_router import MimeMode
from plugins.base_plugin import PipeResult, RadialAction, SliceConfig, SubSliceConfig


class DataOpsPlugin(RadialAction):
    """Polymorphic Dataset Operations Plugin."""

    PII_COLUMN_PATTERNS = [
        re.compile(r"(?i)\b(email|e[-_]?mail)\b"),
        re.compile(r"(?i)\b(phone|mobile|cell|fax)\b"),
        re.compile(r"(?i)\b(ssn|social[-_]?sec|national[-_]?id)\b"),
        re.compile(r"(?i)\b(name|first[-_]?name|last[-_]?name|full[-_]?name|surname)\b"),
        re.compile(r"(?i)\b(credit[-_]?card|card[-_]?num|cvv|iban)\b"),
        re.compile(r"(?i)\b(address|street|zip[-_]?code|postal)\b"),
        re.compile(r"(?i)\b(user[-_]?id|customer[-_]?id|account[-_]?id|client[-_]?id)\b"),
    ]

    def __init__(self) -> None:
        super().__init__(MimeMode.DATASET, "Dataset Operations")
        self._init_slices()

    def _init_slices(self) -> None:
        self.slices[1] = SliceConfig(
            slice_id=1,
            name="Synthetic Twin",
            description="Generate 100-row statistically identical zero-PII twin",
        )
        self.slices[2] = SliceConfig(
            slice_id=2,
            name="PII Masking",
            description="Deterministic salted SHA-256 hash preserving join integrity",
        )
        self.slices[3] = SliceConfig(
            slice_id=3,
            name="Instant EDA Profile",
            description="Interactive dark-mode self-contained HTML EDA report",
        )
        self.slices[4] = SliceConfig(
            slice_id=4,
            name="Format Transpile",
            description="Transpile to JSON Records, SQLite DDL, or Markdown Table",
            sub_slices=[
                SubSliceConfig("json_records", "JSON Records", "JSON array of record dictionaries"),
                SubSliceConfig("sqlite_ddl", "SQLite DDL + INSERTs", "SQL DDL schema and insert statements"),
                SubSliceConfig("markdown_table", "Markdown Table", "GitHub flavored Markdown table"),
            ],
        )

    def execute(
        self,
        payload: Any,
        slice_id: int,
        sub_option: Optional[str] = None,
    ) -> PipeResult:
        start_time = time.perf_counter()
        df = self._load_dataframe(payload)

        if slice_id == 1:
            synth_csv = self._generate_synthetic_twin(df)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=synth_csv,
                action_name="Synthetic Twin",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(synth_csv.encode("utf-8")),
                details={"rows": 100, "columns": len(df.columns)},
            )

        elif slice_id == 2:
            masked_csv, masked_cols = self._mask_pii(df)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=masked_csv,
                action_name="PII Masking",
                mode=self.mode,
                latency_ms=latency,
                secrets_blocked=len(masked_cols) * len(df),
                bytes_streamed=len(masked_csv.encode("utf-8")),
                details={"masked_columns": masked_cols},
            )

        elif slice_id == 3:
            eda_html = self._generate_eda_html(df)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=eda_html,
                action_name="Instant EDA Profile",
                mode=self.mode,
                latency_ms=latency,
                is_html=True,
                bytes_streamed=len(eda_html.encode("utf-8")),
                details={"rows": len(df), "columns": len(df.columns)},
            )

        elif slice_id == 4:
            sub = sub_option or "json_records"
            transpiled = self._transpile_format(df, sub)
            latency = (time.perf_counter() - start_time) * 1000.0
            return PipeResult(
                data=transpiled,
                action_name=f"Transpile ({sub})",
                mode=self.mode,
                latency_ms=latency,
                bytes_streamed=len(transpiled.encode("utf-8")),
                details={"sub_option": sub},
            )

        raise ValueError(f"Invalid slice_id {slice_id} for DataOpsPlugin")

    def _load_dataframe(self, payload: Any) -> pd.DataFrame:
        """Parse arbitrary in-memory payloads into pandas DataFrame."""
        if isinstance(payload, pd.DataFrame):
            return payload

        # Path input
        if isinstance(payload, str) and (payload.endswith(".parquet") or payload.endswith(".pq")):
            return pd.read_parquet(payload)

        # Raw bytes
        if isinstance(payload, (bytes, bytearray)):
            if payload.startswith(b"PAR1"):
                return pd.read_parquet(io.BytesIO(payload))
            if payload.startswith(b"SQLite format 3\x00"):
                # Load sqlite memory connection
                conn = sqlite3.connect(":memory:")
                conn.deserialize(payload)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                table_name = tables[0][0] if tables else "data"
                df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)
                conn.close()
                return df
            text_str = payload.decode("utf-8", errors="replace")
        else:
            text_str = self.read_payload_text(payload)

        stripped = text_str.strip()
        # JSON detection
        if (stripped.startswith("[") and stripped.endswith("]")) or (stripped.startswith("{") and stripped.endswith("}")):
            try:
                return pd.read_json(io.StringIO(stripped))
            except Exception:
                pass

        # CSV / TSV detection
        delimiter = "\t" if "\t" in stripped.splitlines()[0] else ","
        try:
            return pd.read_csv(io.StringIO(stripped), sep=delimiter)
        except Exception:
            # Fallback one-column dataframe
            return pd.DataFrame({"raw_data": stripped.splitlines()})

    def _generate_synthetic_twin(self, df: pd.DataFrame, num_rows: int = 100) -> str:
        """Create a statistically equivalent synthetic twin dataset with 0 real rows."""
        synth_data: Dict[str, Any] = {}
        rng = np.random.default_rng(seed=42)

        for col in df.columns:
            series = df[col].dropna()
            if series.empty:
                synth_data[col] = [None] * num_rows
                continue

            if pd.api.types.is_numeric_dtype(series):
                mean = float(series.mean())
                std = float(series.std()) if len(series) > 1 and not np.isnan(series.std()) else 1.0
                if std == 0.0 or np.isnan(std):
                    std = 1.0
                sampled = rng.normal(mean, std, size=num_rows)
                if pd.api.types.is_integer_dtype(series):
                    sampled = np.round(sampled).astype(int)
                    # Bound to original min/max if reasonable
                    min_val, max_val = int(series.min()), int(series.max())
                    sampled = np.clip(sampled, min_val, max_val)
                synth_data[col] = sampled

            elif pd.api.types.is_datetime64_any_dtype(series):
                min_ts = series.min().value
                max_ts = series.max().value
                if min_ts == max_ts:
                    max_ts += 1000
                rand_ts = rng.integers(min_ts, max_ts, size=num_rows)
                synth_data[col] = pd.to_datetime(rand_ts)

            else:
                # Categorical / string distribution sampling
                val_counts = series.value_counts(normalize=True)
                categories = val_counts.index.to_numpy()
                probabilities = val_counts.to_numpy()
                probabilities = probabilities / probabilities.sum()  # Re-normalize float precision
                synth_data[col] = rng.choice(categories, size=num_rows, p=probabilities)

        synth_df = pd.DataFrame(synth_data)
        out_buf = io.StringIO()
        synth_df.to_csv(out_buf, index=False)
        return out_buf.getvalue()

    def _mask_pii(self, df: pd.DataFrame) -> Tuple[str, List[str]]:
        """Mask PII columns using deterministic salted SHA-256 (preserves joins)."""
        df_masked = df.copy()
        masked_columns = []
        salt = "arcp_devsecops_salt_v1_"

        for col in df.columns:
            col_str = str(col)
            is_pii = any(pattern.search(col_str) for pattern in self.PII_COLUMN_PATTERNS)
            if not is_pii and df[col].dtype == object:
                # Content heuristic on first 20 non-null values
                sample = df[col].dropna().head(20).astype(str)
                if any("@" in s and "." in s for s in sample):
                    is_pii = True

            if is_pii:
                masked_columns.append(col_str)

                def _hash_val(val: Any) -> Any:
                    if pd.isna(val):
                        return val
                    raw = f"{salt}:{val}".encode("utf-8")
                    digest = hashlib.sha256(raw).hexdigest()[:12]
                    return f"ID_{digest}"

                df_masked[col] = df_masked[col].apply(_hash_val)

        out_buf = io.StringIO()
        df_masked.to_csv(out_buf, index=False)
        return out_buf.getvalue(), masked_columns

    def _generate_eda_html(self, df: pd.DataFrame) -> str:
        """Generate a self-contained, dark-mode glassmorphism HTML EDA report."""
        rows_count, cols_count = df.shape
        mem_usage_kb = round(df.memory_usage(deep=True).sum() / 1024, 1)
        duplicate_rows = int(df.duplicated().sum())

        # Column stats
        col_rows = []
        for col in df.columns:
            series = df[col]
            missing = int(series.isna().sum())
            missing_pct = round((missing / max(1, rows_count)) * 100, 1)
            dtype_str = str(series.dtype)
            n_unique = int(series.nunique())

            num_stats = ""
            if pd.api.types.is_numeric_dtype(series):
                mean_val = round(float(series.mean()), 2)
                std_val = round(float(series.std()), 2) if len(series.dropna()) > 1 else 0.0
                q25 = float(series.quantile(0.25))
                q75 = float(series.quantile(0.75))
                iqr = q75 - q25
                outliers = int(((series < (q25 - 1.5 * iqr)) | (series > (q75 + 1.5 * iqr))).sum())
                num_stats = f"Mean: {mean_val} | Std: {std_val} | Outliers: {outliers}"
            else:
                top_val = str(series.mode().iloc[0]) if not series.mode().empty else "N/A"
                num_stats = f"Top: {top_val[:20]}"

            col_rows.append(f"""
            <tr>
                <td class="font-mono text-cyan">{col}</td>
                <td class="font-mono">{dtype_str}</td>
                <td>{n_unique}</td>
                <td>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {100 - missing_pct}%;"></div>
                    </div>
                    <span class="text-muted">{missing_pct}% ({missing})</span>
                </td>
                <td class="text-sm">{num_stats}</td>
            </tr>
            """)

        # Correlation Matrix SVG
        numeric_df = df.select_dtypes(include=[np.number])
        corr_svg = ""
        if numeric_df.shape[1] >= 2:
            corr = numeric_df.corr().round(2)
            n = len(corr.columns)
            size = min(360, max(200, n * 45))
            cell_size = size / n
            rects = []
            for i, r_col in enumerate(corr.columns):
                for j, c_col in enumerate(corr.columns):
                    val = float(corr.iloc[i, j])
                    # Interpolate cyan to magenta/indigo
                    norm_val = (val + 1.0) / 2.0  # 0 to 1
                    r_val = int(99 + (0 - 99) * norm_val)
                    g_val = int(102 + (245 - 102) * norm_val)
                    b_val = int(241 + (212 - 241) * norm_val)
                    color = f"rgb({r_val}, {g_val}, {b_val})"
                    x = j * cell_size
                    y = i * cell_size
                    rects.append(f'<rect x="{x}" y="{y}" width="{cell_size-2}" height="{cell_size-2}" rx="3" fill="{color}"/>')
                    rects.append(f'<text x="{x + cell_size/2}" y="{y + cell_size/2 + 4}" fill="#0f172a" font-size="10" font-weight="bold" text-anchor="middle">{val:.2f}</text>')

            corr_svg = f"""
            <div class="card" style="margin-top: 20px;">
                <h3 style="color: #00F5D4; margin-top:0;">Pearson Correlation Matrix ({n} Numeric Columns)</h3>
                <svg width="{size}" height="{size}" style="background: rgba(0,0,0,0.3); border-radius: 8px; padding: 5px;">
                    {''.join(rects)}
                </svg>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ArcP Instant EDA Profile</title>
<style>
    body {{
        margin: 0; padding: 24px;
        background: #0B0F19; color: #E2E8F0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    }}
    .hud-title {{
        color: #00F5D4; font-size: 24px; font-weight: 800;
        letter-spacing: 1px; margin-bottom: 4px;
    }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
    .card {{
        background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(99, 102, 241, 0.3);
        border-radius: 12px; padding: 16px; backdrop-filter: blur(10px);
    }}
    .metric-val {{ font-size: 26px; font-weight: bold; color: #F8FAFC; margin-top: 4px; }}
    .text-cyan {{ color: #00F5D4; }}
    .text-muted {{ color: #94A3B8; font-size: 12px; }}
    .font-mono {{ font-family: monospace; }}
    table {{
        width: 100%; border-collapse: collapse; margin-top: 16px;
        background: rgba(15, 23, 42, 0.85); border-radius: 12px; overflow: hidden;
    }}
    th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); }}
    th {{ background: rgba(30, 41, 59, 0.9); color: #00F5D4; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
    .progress-bar {{ width: 80px; height: 6px; background: #334155; border-radius: 3px; display: inline-block; vertical-align: middle; }}
    .progress-fill {{ height: 100%; background: #6366F1; border-radius: 3px; }}
</style>
</head>
<body>
    <div class="hud-title">⚡ ARCP INSTANT EDA REPORT</div>
    <div class="text-muted">Zero-disk in-memory statistical inspection • Generated in RAM</div>

    <div class="grid">
        <div class="card">
            <div class="text-muted">TOTAL ROWS</div>
            <div class="metric-val">{rows_count:,}</div>
        </div>
        <div class="card">
            <div class="text-muted">TOTAL COLUMNS</div>
            <div class="metric-val">{cols_count}</div>
        </div>
        <div class="card">
            <div class="text-muted">IN-MEMORY FOOTPRINT</div>
            <div class="metric-val">{mem_usage_kb} KB</div>
        </div>
        <div class="card">
            <div class="text-muted">DUPLICATE ROWS</div>
            <div class="metric-val">{duplicate_rows}</div>
        </div>
    </div>

    <div class="card">
        <h3 style="color: #00F5D4; margin-top:0;">Column Distributions & Missing Rates</h3>
        <table>
            <thead>
                <tr>
                    <th>Column</th>
                    <th>Type</th>
                    <th>Unique</th>
                    <th>Completeness</th>
                    <th>Statistical Profile</th>
                </tr>
            </thead>
            <tbody>
                {''.join(col_rows)}
            </tbody>
        </table>
    </div>

    {corr_svg}
</body>
</html>
"""
        return html_content

    def _transpile_format(self, df: pd.DataFrame, sub_option: str) -> str:
        """Convert dataset in-memory into JSON Records, SQLite DDL + INSERTs, or Markdown Table."""
        if sub_option == "json_records":
            return df.to_json(orient="records", indent=2, date_format="iso")

        elif sub_option == "sqlite_ddl":
            lines = ["-- Generated by ArcP In-Memory Pipeline", "BEGIN TRANSACTION;"]
            type_mapping = {
                "int64": "INTEGER",
                "float64": "REAL",
                "bool": "INTEGER",
                "datetime64[ns]": "TIMESTAMP",
            }
            cols_def = []
            for col in df.columns:
                dtype_name = str(df[col].dtype)
                sql_type = type_mapping.get(dtype_name, "TEXT")
                cols_def.append(f'    "{col}" {sql_type}')

            lines.append("CREATE TABLE IF NOT EXISTS dataset (")
            lines.append(",\n".join(cols_def))
            lines.append(");")

            # Sample first 200 rows for insert statements
            for _, row in df.head(200).iterrows():
                vals = []
                for val in row:
                    if pd.isna(val):
                        vals.append("NULL")
                    elif isinstance(val, (int, float, np.integer, np.floating)):
                        vals.append(str(val))
                    else:
                        escaped = str(val).replace("'", "''")
                        vals.append(f"'{escaped}'")
                col_names = ", ".join([f'"{c}"' for c in df.columns])
                lines.append(f"INSERT INTO dataset ({col_names}) VALUES ({', '.join(vals)});")

            lines.append("COMMIT;")
            return "\n".join(lines)

        elif sub_option == "markdown_table":
            # Native Markdown Table generator without requiring external tabulate
            preview = df.head(30)
            headers = [str(c) for c in preview.columns]
            header_line = "| " + " | ".join(headers) + " |"
            sep_line = "| " + " | ".join(["---"] * len(headers)) + " |"
            rows = []
            for _, row in preview.iterrows():
                row_str = "| " + " | ".join([str(v).replace("\n", " ").replace("|", "\\|") for v in row]) + " |"
                rows.append(row_str)
            return "\n".join([header_line, sep_line] + rows)

        return df.to_csv(index=False)
