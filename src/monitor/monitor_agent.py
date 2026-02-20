"""
Monitor Agent (src/monitor/monitor_agent.py)

A Pi-engine-backed agent that:
  1. Lists all configured alert rules
  2. Evaluates each rule against live data
  3. Sends notifications for any triggered alerts
  4. Returns a summary report

Use build_monitor_agent() to get a fully-wired PiEngine, or use
MonitorAgent directly for lightweight (no-LLM) operation.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from src.core.engine import PiEngine
from src.extensions.sandbox import SecuritySandbox
from src.monitor.alert_config import AlertRule, load_rules
from src.monitor.evaluator import AlertResult, RuleEvaluator
from src.monitor.notifier import AlertNotifier

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System Prompt
# ---------------------------------------------------------------------------

MONITOR_SYSTEM_PROMPT = """
You are "Pi-Monitor", an autonomous monitoring agent.

Your job on each cycle:
1. LIST    — Call `list_rules` to see all active alert rules.
2. EVALUATE — Call `evaluate_rules` to check every rule against live data.
3. NOTIFY  — For each triggered alert, call `send_alert` to dispatch notifications.
4. REPORT  — Summarise the cycle: how many rules checked, how many fired, which ones.

Rules:
- Always explain what you are checking before calling a tool.
- If a rule evaluation fails, log the error and continue to the next rule.
- Never skip sending a notification for a triggered + non-suppressed alert.
- End with a concise cycle summary.
"""

# ---------------------------------------------------------------------------
# MonitorAgent — lightweight, no-LLM mode
# ---------------------------------------------------------------------------

class MonitorAgent:
    """Lightweight monitor that evaluates rules and fires alerts without an LLM.

    Args:
        rules_path: Path to the JSON alert rules config.
        dry_run: If True, no real AWS/DB/notification calls are made.
    """

    def __init__(
        self,
        rules_path: str = "configs/alerts.json",
        dry_run: bool = False,
    ):
        self.rules_path = rules_path
        self.dry_run = dry_run
        self._evaluator = RuleEvaluator(dry_run=dry_run)
        self._notifier = AlertNotifier()

    def run_cycle(self) -> str:
        """Run one full monitoring cycle: load → evaluate → notify → report.

        Returns:
            A plain-text summary of the cycle results.
        """
        logger.info("MonitorAgent: starting cycle (dry_run=%s).", self.dry_run)

        try:
            rules = load_rules(self.rules_path)
        except FileNotFoundError as exc:
            msg = f"MonitorAgent: could not load rules — {exc}"
            logger.error(msg)
            return msg

        if not rules:
            return "MonitorAgent: no enabled rules found. Nothing to evaluate."

        results = self._evaluator.evaluate_all(rules)

        triggered = [r for r in results if r.triggered and not r.suppressed]
        suppressed = [r for r in results if r.suppressed]
        ok = [r for r in results if not r.triggered and not r.suppressed]
        errors = [r for r in results if "ERROR" in r.message and not r.triggered]

        if not self.dry_run:
            self._notifier.send_all(triggered)

        lines = [
            f"=== Pi-Monitor Cycle Report ===",
            f"Rules evaluated : {len(results)}",
            f"Triggered       : {len(triggered)}",
            f"OK              : {len(ok)}",
            f"Suppressed      : {len(suppressed)}",
            f"Errors          : {len(errors)}",
            "",
        ]

        if triggered:
            lines.append("🔴 Triggered Alerts:")
            for r in triggered:
                lines.append(f"  • {r.message}")
            lines.append("")

        if errors:
            lines.append("⚠️  Evaluation Errors:")
            for r in errors:
                lines.append(f"  • {r.message}")
            lines.append("")

        summary = "\n".join(lines)
        logger.info("MonitorAgent cycle complete.\n%s", summary)
        return summary


# ---------------------------------------------------------------------------
# Tool implementations for Pi engine
# ---------------------------------------------------------------------------

_active_agent: MonitorAgent | None = None
_active_results: list[AlertResult] = []


def _get_agent() -> MonitorAgent:
    global _active_agent
    if _active_agent is None:
        _active_agent = MonitorAgent(
            rules_path=os.getenv("ALERT_RULES_PATH", "configs/alerts.json"),
            dry_run=False,
        )
    return _active_agent


def list_rules() -> str:
    """List all currently configured and enabled alert rules.

    Returns:
        JSON array of rule summaries.
    """
    try:
        agent = _get_agent()
        rules = load_rules(agent.rules_path)
        summary = [
            {
                "id": r.id,
                "name": r.name,
                "type": r.type,
                "condition": f"{r.condition.operator} {r.condition.threshold}",
                "channels": r.channels,
                "cooldown_minutes": r.cooldown_minutes,
            }
            for r in rules
        ]
        return json.dumps(summary, indent=2)
    except Exception as exc:  # noqa: BLE001
        return f"ERROR listing rules: {exc}"


def evaluate_rules() -> str:
    """Evaluate all enabled alert rules against live data.

    Returns:
        JSON array of evaluation results.
    """
    global _active_results
    try:
        agent = _get_agent()
        rules = load_rules(agent.rules_path)
        _active_results = agent._evaluator.evaluate_all(rules)
        out = [
            {
                "rule_id": r.rule.id,
                "triggered": r.triggered,
                "suppressed": r.suppressed,
                "current_value": r.current_value,
                "message": r.message,
            }
            for r in _active_results
        ]
        return json.dumps(out, indent=2)
    except Exception as exc:  # noqa: BLE001
        return f"ERROR evaluating rules: {exc}"


def send_alert(rule_id: str) -> str:
    """Send notifications for a specific triggered alert rule.

    Args:
        rule_id: The ID of the rule whose alert should be sent.

    Returns:
        Confirmation string or error message.
    """
    global _active_results
    match = next((r for r in _active_results if r.rule.id == rule_id), None)
    if match is None:
        return f"ERROR: No evaluation result found for rule_id='{rule_id}'. Run evaluate_rules first."
    if not match.triggered:
        return f"Rule '{rule_id}' did not trigger — no alert sent."
    if match.suppressed:
        return f"Rule '{rule_id}' is suppressed (in cooldown) — no alert sent."
    try:
        _get_agent()._notifier.send(match)
        return f"OK: Alert sent for rule '{rule_id}' via channels {match.rule.channels}."
    except Exception as exc:  # noqa: BLE001
        return f"ERROR sending alert for '{rule_id}': {exc}"


# ---------------------------------------------------------------------------
# Tool Schemas
# ---------------------------------------------------------------------------

_TOOL_SCHEMAS: dict[str, Any] = {
    "list_rules": {
        "type": "object",
        "properties": {},
        "required": [],
    },
    "evaluate_rules": {
        "type": "object",
        "properties": {},
        "required": [],
    },
    "send_alert": {
        "type": "object",
        "properties": {
            "rule_id": {"type": "string", "description": "ID of the rule to send the alert for"},
        },
        "required": ["rule_id"],
    },
}


# ---------------------------------------------------------------------------
# PiEngine factory
# ---------------------------------------------------------------------------

def build_monitor_agent(
    policy_path: str = "policies/security.json",
    model: str = "gpt-4o",
    rules_path: str = "configs/alerts.json",
    dry_run: bool = False,
) -> PiEngine:
    """Build and return a fully-wired Monitor PiEngine instance.

    Args:
        policy_path: Path to the security policy JSON.
        model: OpenAI model to use.
        rules_path: Path to the alert rules JSON config.
        dry_run: If True, no real AWS/DB/notification calls are made.

    Returns:
        Configured PiEngine ready to call `.run(task)`.
    """
    global _active_agent
    _active_agent = MonitorAgent(rules_path=rules_path, dry_run=dry_run)

    engine = PiEngine(system_prompt=MONITOR_SYSTEM_PROMPT, model=model)
    sandbox = SecuritySandbox(policy_path=policy_path)
    engine.add_interceptor(sandbox)

    tool_map = {
        "list_rules": (list_rules, "List all configured and enabled alert rules"),
        "evaluate_rules": (evaluate_rules, "Evaluate all rules against live metric/log/DB data"),
        "send_alert": (send_alert, "Send notifications for a specific triggered alert rule"),
    }

    for name, (fn, desc) in tool_map.items():
        engine.registry.register(fn, name=name, description=desc, parameters=_TOOL_SCHEMAS[name])

    return engine
