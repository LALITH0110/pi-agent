"""
tests/test_data_agent.py — Integration tests for the DataGhost agent tools.

Uses an in-memory SQLite database so no PostgreSQL is needed.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

# Use SQLite for tests
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from src.agents.data_agent import get_schema, run_query, generate_chart, write_report
from sqlalchemy import create_engine, text


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def use_sqlite_db(monkeypatch, tmp_path):
    """Create a fresh SQLite in-memory DB with sample data for each test."""
    db_path = tmp_path / "test.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", db_url)

    # Seed sample data
    engine = create_engine(db_url)
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY,
                product TEXT,
                amount REAL,
                created_at TEXT
            )
        """))
        conn.execute(text("""
            INSERT INTO orders (product, amount, created_at) VALUES
            ('Widget A', 99.99, '2024-01-01'),
            ('Widget B', 49.99, '2024-01-02'),
            ('Gadget X', 299.99, '2024-01-03')
        """))
        conn.commit()


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    """Override the REPORTS_DIR to use a temp directory."""
    import src.agents.data_agent as da
    monkeypatch.setattr(da, "REPORTS_DIR", tmp_path / "reports")
    return tmp_path / "reports"


# ---------------------------------------------------------------------------
# get_schema
# ---------------------------------------------------------------------------

class TestGetSchema:
    def test_returns_valid_json(self):
        result = get_schema()
        data = json.loads(result)
        assert "orders" in data

    def test_schema_has_correct_columns(self):
        result = get_schema()
        data = json.loads(result)
        col_names = [c["name"] for c in data["orders"]]
        assert "id" in col_names
        assert "product" in col_names
        assert "amount" in col_names


# ---------------------------------------------------------------------------
# run_query
# ---------------------------------------------------------------------------

class TestRunQuery:
    def test_select_all(self):
        result = run_query("SELECT * FROM orders")
        rows = json.loads(result)
        assert len(rows) == 3

    def test_select_with_filter(self):
        result = run_query("SELECT product FROM orders WHERE amount > 100")
        rows = json.loads(result)
        assert len(rows) == 1
        assert rows[0]["product"] == "Gadget X"

    def test_blocks_non_select(self):
        result = run_query("DELETE FROM orders")
        assert "ERROR" in result

    def test_blocks_insert(self):
        result = run_query("INSERT INTO orders VALUES (99, 'X', 1.0, '2024-01-01')")
        assert "ERROR" in result


# ---------------------------------------------------------------------------
# generate_chart
# ---------------------------------------------------------------------------

class TestGenerateChart:
    def test_generates_bar_chart(self, reports_dir):
        data = json.dumps([
            {"product": "Widget A", "amount": 99.99},
            {"product": "Widget B", "amount": 49.99},
        ])
        result = generate_chart(data, x_key="product", y_key="amount", title="Test Chart", filename="test_bar")
        assert result.endswith(".png")
        assert Path(result).exists()

    def test_generates_line_chart(self, reports_dir):
        data = json.dumps([
            {"product": "Widget A", "amount": 99.99},
            {"product": "Widget B", "amount": 49.99},
        ])
        result = generate_chart(data, x_key="product", y_key="amount", chart_type="line", filename="test_line")
        assert Path(result).exists()

    def test_handles_bad_json(self, reports_dir):
        result = generate_chart("not-json", x_key="a", y_key="b")
        assert "ERROR" in result

    def test_handles_missing_key(self, reports_dir):
        data = json.dumps([{"x": 1}])
        result = generate_chart(data, x_key="wrong_key", y_key="also_wrong")
        assert "ERROR" in result


# ---------------------------------------------------------------------------
# write_report
# ---------------------------------------------------------------------------

class TestWriteReport:
    def test_writes_markdown_file(self, reports_dir):
        content = "# Test Report\n\nThis is a test."
        path = write_report(content, filename="test_report")
        assert Path(path).exists()
        assert Path(path).read_text() == content

    def test_auto_generates_filename(self, reports_dir):
        path = write_report("# Auto")
        assert Path(path).exists()
        assert "report_" in path
