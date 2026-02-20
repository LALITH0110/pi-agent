"""
Data Ghost Agent (src/agents/data_agent.py)

A proactive "Data Ghost" analyst that:
  - Introspects the database schema automatically
  - Detects new tables / columns / data patterns
  - Runs analytical SQL queries
  - Generates Matplotlib charts saved to /reports/
  - Writes Markdown summary reports to /reports/
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, inspect, text  # type: ignore
from sqlalchemy.exc import SQLAlchemyError  # type: ignore

from src.core.engine import PiEngine
from src.extensions.sandbox import SecuritySandbox

logger = logging.getLogger(__name__)

REPORTS_DIR = Path("reports")

# ---------------------------------------------------------------------------
# System Prompt
# ---------------------------------------------------------------------------

DATA_GHOST_SYSTEM_PROMPT = """
You are "Pi-DataGhost", a proactive data analyst agent embedded in a database layer.

Your mission on each heartbeat cycle:
1. DISCOVER  — Introspect the schema. Note any new tables or column changes since last run.
2. ANALYSE   — Run 3–5 analytical SQL queries that surface meaningful patterns or anomalies
               (growth trends, top N, outliers, nullability issues, data freshness, etc.).
3. VISUALISE — For the most interesting finding, generate a chart with `generate_chart`.
4. REPORT    — Write a Markdown summary of your findings with `write_report`.

Rules:
- Only run SELECT queries. Never write, update, or delete data.
- Keep queries focused and efficient (use LIMIT if exploring unknown table sizes).
- Explain your reasoning before calling each tool.
- End with a concise executive summary in plain English.
"""

# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _get_db_engine():
    """Return a SQLAlchemy engine from DATABASE_URL env var."""
    url = os.getenv("DATABASE_URL", "sqlite:///dev.db")
    return create_engine(url)


def get_schema() -> str:
    """Introspect the database and return a structured schema description.

    Returns:
        JSON string describing all tables and their columns.
    """
    try:
        engine = _get_db_engine()
        inspector = inspect(engine)
        schema: dict[str, list[dict]] = {}

        for table_name in inspector.get_table_names():
            cols = []
            for col in inspector.get_columns(table_name):
                cols.append({
                    "name": col["name"],
                    "type": str(col["type"]),
                    "nullable": col.get("nullable", True),
                })
            schema[table_name] = cols

        return json.dumps(schema, indent=2)
    except SQLAlchemyError as exc:
        return f"ERROR introspecting schema: {exc}"


def run_query(sql: str) -> str:
    """Execute a read-only SQL query and return the results as JSON.

    Args:
        sql: A SELECT SQL statement to execute.

    Returns:
        JSON array of result rows (up to 500 rows), or an error message.
    """
    sql_upper = sql.strip().upper()
    # Safety guard — reject anything that isn't a SELECT
    if not sql_upper.startswith("SELECT") and not sql_upper.startswith("WITH"):
        return "ERROR: Only SELECT (or WITH ... SELECT) queries are permitted."

    try:
        engine = _get_db_engine()
        with engine.connect() as conn:
            result = conn.execute(text(sql))
            cols = list(result.keys())
            rows = [dict(zip(cols, row)) for row in result.fetchmany(500)]
        return json.dumps(rows, indent=2, default=str)
    except SQLAlchemyError as exc:
        return f"ERROR running query: {exc}"


def generate_chart(
    data_json: str,
    x_key: str,
    y_key: str,
    chart_type: str = "bar",
    title: str = "Chart",
    filename: str | None = None,
) -> str:
    """Generate a Matplotlib chart from JSON data and save it to /reports/.

    Args:
        data_json: JSON array of objects (same format as run_query output).
        x_key: Key to use for the X-axis.
        y_key: Key to use for the Y-axis.
        chart_type: 'bar' or 'line' (default 'bar').
        title: Chart title.
        filename: Output filename (without extension). Auto-generated if omitted.

    Returns:
        Path to the saved chart file, or an error message.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")  # Non-interactive backend  # noqa: E402
        import matplotlib.pyplot as plt  # type: ignore
    except ImportError:
        return "ERROR: matplotlib is not installed. Run: pip install matplotlib"

    try:
        data = json.loads(data_json)
    except json.JSONDecodeError as exc:
        return f"ERROR: Invalid JSON data — {exc}"

    if not data:
        return "ERROR: No data provided for chart."

    try:
        x_vals = [str(row[x_key]) for row in data]
        y_vals = [float(row[y_key]) for row in data]
    except (KeyError, ValueError) as exc:
        return f"ERROR: Could not extract chart data — {exc}"

    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = filename or f"chart_{ts}"
    out_path = REPORTS_DIR / f"{fname}.png"

    fig, ax = plt.subplots(figsize=(10, 5))
    if chart_type == "line":
        ax.plot(x_vals, y_vals, marker="o", linewidth=2)
    else:
        ax.bar(x_vals, y_vals)

    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.set_xlabel(x_key)
    ax.set_ylabel(y_key)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close(fig)

    logger.info("Chart saved to %s", out_path)
    return str(out_path)


def write_report(content: str, filename: str | None = None) -> str:
    """Write a Markdown report to /reports/.

    Args:
        content: Full Markdown content of the report.
        filename: Output filename (without extension). Auto-generated if omitted.

    Returns:
        Path to the saved report file.
    """
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = filename or f"report_{ts}"
    out_path = REPORTS_DIR / f"{fname}.md"
    out_path.write_text(content)
    logger.info("Report saved to %s", out_path)
    return str(out_path)


# ---------------------------------------------------------------------------
# Tool Schemas
# ---------------------------------------------------------------------------

_TOOL_SCHEMAS = {
    "get_schema": {
        "type": "object",
        "properties": {},
        "required": [],
    },
    "run_query": {
        "type": "object",
        "properties": {
            "sql": {"type": "string", "description": "A SELECT SQL statement to execute"},
        },
        "required": ["sql"],
    },
    "generate_chart": {
        "type": "object",
        "properties": {
            "data_json": {"type": "string", "description": "JSON array of row objects"},
            "x_key": {"type": "string", "description": "Key for the X-axis"},
            "y_key": {"type": "string", "description": "Key for the Y-axis"},
            "chart_type": {"type": "string", "enum": ["bar", "line"], "description": "Chart type (default: bar)"},
            "title": {"type": "string", "description": "Chart title"},
            "filename": {"type": "string", "description": "Output filename (no extension)"},
        },
        "required": ["data_json", "x_key", "y_key"],
    },
    "write_report": {
        "type": "object",
        "properties": {
            "content": {"type": "string", "description": "Markdown content of the report"},
            "filename": {"type": "string", "description": "Output filename (no extension)"},
        },
        "required": ["content"],
    },
}

# ---------------------------------------------------------------------------
# DataGhostAgent factory
# ---------------------------------------------------------------------------

def build_data_ghost_agent(
    policy_path: str = "policies/security.json",
    model: str = "gpt-4o",
) -> PiEngine:
    """Build and return a fully-wired DataGhost PiEngine instance.

    Args:
        policy_path: Path to the security policy JSON.
        model: OpenAI model to use.

    Returns:
        Configured PiEngine ready to call `.run(task)`.
    """
    engine = PiEngine(system_prompt=DATA_GHOST_SYSTEM_PROMPT, model=model)
    sandbox = SecuritySandbox(policy_path=policy_path)
    engine.add_interceptor(sandbox)

    tool_map = {
        "get_schema": (get_schema, "Introspect and return the full database schema as JSON"),
        "run_query": (run_query, "Execute a read-only SQL SELECT query and return results as JSON"),
        "generate_chart": (generate_chart, "Generate a Matplotlib bar or line chart from JSON data"),
        "write_report": (write_report, "Write a Markdown report file to the /reports/ directory"),
    }

    for name, (fn, desc) in tool_map.items():
        engine.registry.register(fn, name=name, description=desc, parameters=_TOOL_SCHEMAS[name])

    return engine
