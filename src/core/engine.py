"""
Pi Engine — Minimalist Agentic Loop

The core of pi-agent. Provides:
  - ToolRegistry: register Python callables as LLM-callable tools
  - PiEngine: runs the messages → LLM → tool calls → messages loop
  - Extension support: wrap tool execution with interceptors (e.g. SecuritySandbox)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from openai import OpenAI

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool representation
# ---------------------------------------------------------------------------

@dataclass
class Tool:
    """A callable registered with the engine."""
    name: str
    description: str
    parameters: dict          # JSON-Schema object describing the parameters
    fn: Callable[..., Any]

    def to_openai_schema(self) -> dict:
        """Convert to the OpenAI function-calling tool schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


# ---------------------------------------------------------------------------
# Tool Registry
# ---------------------------------------------------------------------------

class ToolRegistry:
    """Central registry for all tools available to an agent."""

    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        description: str = "",
        parameters: dict | None = None,
    ) -> "ToolRegistry":
        """Register a callable as a tool.

        Args:
            fn: The Python function to expose as a tool.
            name: Override the tool name (defaults to fn.__name__).
            description: Human-readable description shown to the LLM.
            parameters: JSON-Schema ``object`` describing the function arguments.
        """
        tool_name = name or fn.__name__
        schema = parameters or {
            "type": "object",
            "properties": {},
            "required": [],
        }
        self._tools[tool_name] = Tool(
            name=tool_name,
            description=description,
            parameters=schema,
            fn=fn,
        )
        logger.debug("Registered tool: %s", tool_name)
        return self

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all_schemas(self) -> list[dict]:
        return [t.to_openai_schema() for t in self._tools.values()]

    def __len__(self) -> int:
        return len(self._tools)


# ---------------------------------------------------------------------------
# Extension / Interceptor interface
# ---------------------------------------------------------------------------

class ToolInterceptor:
    """Base class for tool execution interceptors.

    Subclasses override ``before_call`` to inspect or mutate the call,
    or raise an exception to block it.
    """

    def before_call(self, tool_name: str, arguments: dict) -> dict:
        """Called before the tool function is invoked.

        Returns the (possibly modified) arguments dict, or raises to block.
        """
        return arguments

    def after_call(self, tool_name: str, result: Any) -> Any:
        """Called after the tool function returns. Can modify or log the result."""
        return result


# ---------------------------------------------------------------------------
# Pi Engine
# ---------------------------------------------------------------------------

class PiEngine:
    """Minimalist agentic loop powered by OpenAI function-calling.

    Usage::

        engine = PiEngine(system_prompt="You are an SRE agent.")
        engine.registry.register(my_tool_fn, description="Does X", parameters={...})
        engine.add_interceptor(my_sandbox)
        result = engine.run("Investigate the 5xx spike from the last hour.")
        print(result)
    """

    def __init__(
        self,
        system_prompt: str,
        model: str = "gpt-4o",
        max_iterations: int = 20,
        api_key: str | None = None,
    ):
        self.system_prompt = system_prompt
        self.model = model
        self.max_iterations = max_iterations
        self.registry = ToolRegistry()
        self._interceptors: list[ToolInterceptor] = []
        self._client = OpenAI(api_key=api_key)  # picks up OPENAI_API_KEY from env

    def add_interceptor(self, interceptor: ToolInterceptor) -> "PiEngine":
        self._interceptors.append(interceptor)
        return self

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _execute_tool(self, tool_name: str, raw_args: str) -> str:
        """Resolve, intercept, and call a tool. Always returns a string."""
        tool = self.registry.get(tool_name)
        if tool is None:
            return f"ERROR: Unknown tool '{tool_name}'"

        try:
            arguments: dict = json.loads(raw_args) if raw_args else {}
        except json.JSONDecodeError as exc:
            return f"ERROR: Could not parse tool arguments — {exc}"

        # Run before-call interceptors
        for interceptor in self._interceptors:
            try:
                arguments = interceptor.before_call(tool_name, arguments)
            except BlockedCommandError as exc:
                logger.warning("Tool '%s' blocked by interceptor: %s", tool_name, exc)
                return str(exc)

        # Execute the tool
        try:
            result = tool.fn(**arguments)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Tool '%s' raised an exception", tool_name)
            result = f"ERROR: {exc}"

        # Run after-call interceptors
        for interceptor in self._interceptors:
            result = interceptor.after_call(tool_name, result)

        return str(result)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, user_message: str, extra_context: str = "") -> str:
        """Run the agentic loop for the given user message.

        Args:
            user_message: The task description / question from a human or scheduler.
            extra_context: Optional extra system context appended to the system prompt.

        Returns:
            The final text response from the model after all tool calls are resolved.
        """
        system = self.system_prompt
        if extra_context:
            system += f"\n\n{extra_context}"

        messages: list[dict] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ]
        tools = self.registry.all_schemas()

        for iteration in range(self.max_iterations):
            logger.debug("Engine iteration %d/%d", iteration + 1, self.max_iterations)

            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=tools or None,
                tool_choice="auto" if tools else None,
            )

            message = response.choices[0].message
            messages.append(message.model_dump(exclude_unset=False))

            # No tool calls → model is done
            if not message.tool_calls:
                logger.info("Engine finished after %d iteration(s).", iteration + 1)
                return message.content or ""

            # Handle each tool call
            for tc in message.tool_calls:
                logger.info("Tool call: %s(%s)", tc.function.name, tc.function.arguments[:120])
                result = self._execute_tool(tc.function.name, tc.function.arguments)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })

        logger.warning("Engine hit max_iterations (%d). Returning last assistant message.", self.max_iterations)
        # Return whatever the last assistant content was
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("role") == "assistant" and msg.get("content"):
                return msg["content"]
        return "Agent reached maximum iterations without a final response."


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class BlockedCommandError(RuntimeError):
    """Raised by an interceptor when a command must be fully blocked."""
