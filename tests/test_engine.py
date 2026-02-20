"""
tests/test_engine.py — Unit tests for the Pi engine core.

Uses a mock LLM client so no real API calls are made.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from src.core.engine import PiEngine, ToolRegistry, Tool


# ---------------------------------------------------------------------------
# ToolRegistry
# ---------------------------------------------------------------------------

class TestToolRegistry:
    def test_register_and_retrieve(self):
        reg = ToolRegistry()
        fn = lambda x: x * 2  # noqa: E731
        reg.register(fn, name="double", description="Doubles a number",
                     parameters={"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"]})
        tool = reg.get("double")
        assert tool is not None
        assert tool.name == "double"
        assert tool.fn(3) == 6

    def test_all_schemas_format(self):
        reg = ToolRegistry()
        reg.register(lambda: None, name="noop", description="Does nothing",
                     parameters={"type": "object", "properties": {}, "required": []})
        schemas = reg.all_schemas()
        assert len(schemas) == 1
        assert schemas[0]["type"] == "function"
        assert schemas[0]["function"]["name"] == "noop"

    def test_unknown_tool_returns_none(self):
        reg = ToolRegistry()
        assert reg.get("nonexistent") is None

    def test_len(self):
        reg = ToolRegistry()
        reg.register(lambda: None, name="a", description="")
        reg.register(lambda: None, name="b", description="")
        assert len(reg) == 2


# ---------------------------------------------------------------------------
# PiEngine tool execution
# ---------------------------------------------------------------------------

class TestPiEngineToolExecution:
    def setup_method(self):
        with patch("src.core.engine.OpenAI"):
            self.engine = PiEngine(system_prompt="Test")
        self.engine.registry.register(
            lambda x: f"echo:{x}",
            name="echo",
            description="Echoes input",
            parameters={"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]},
        )

    def test_execute_known_tool(self):
        result = self.engine._execute_tool("echo", json.dumps({"x": "hello"}))
        assert result == "echo:hello"

    def test_execute_unknown_tool(self):
        result = self.engine._execute_tool("unknown_tool", "{}")
        assert "ERROR" in result
        assert "Unknown tool" in result

    def test_execute_bad_json_args(self):
        result = self.engine._execute_tool("echo", "not-valid-json")
        assert "ERROR" in result

    def test_execute_tool_exception(self):
        def boom(**kwargs):
            raise ValueError("Something went wrong!")
        self.engine.registry.register(boom, name="bomb", description="Explodes")
        result = self.engine._execute_tool("bomb", "{}")
        assert "ERROR" in result
        assert "Something went wrong" in result
