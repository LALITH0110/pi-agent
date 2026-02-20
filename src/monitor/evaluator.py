"""
Rule Evaluator (src/monitor/evaluator.py)

Evaluates each AlertRule against live data:
  - metric      → CloudWatch metric data (avg / max)
  - log_keyword → CloudWatch log scan for keyword occurrences
  - db_query    → SQL query result value compared to threshold

Returns an AlertResult for each rule. Applies cooldown suppression so
the same alert does not fire repeatedly within its cooldown window.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from src.monitor.alert_config import AlertRule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AlertResult
# ---------------------------------------------------------------------------

@dataclass
class AlertResult:
    """The outcome of evaluating a single rule."""
    rule: AlertRule
    triggered: bool
    current_value: float | None
    message: str
    suppressed: bool = False   # True if in cooldown window


# ---------------------------------------------------------------------------
# RuleEvaluator
# ---------------------------------------------------------------------------

class RuleEvaluator:
    """Evaluates AlertRule objects against live data sources.

    Args:
        dry_run: If True, skip real AWS/DB calls and simulate data.
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        # cooldown_tracker: {rule_id: last_fired_timestamp}
        self._cooldown_tracker: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, rule: AlertRule) -> AlertResult:
        """Evaluate a single rule. Returns an AlertResult.

        Applies cooldown suppression: if the rule fired recently, the result
        will have ``suppressed=True`` and ``triggered=False``.
        """
        if self._in_cooldown(rule):
            return AlertResult(
                rule=rule,
                triggered=False,
                current_value=None,
                message=f"Rule '{rule.id}' is in cooldown (last fired within {rule.cooldown_minutes}m).",
                suppressed=True,
            )

        try:
            result = self._dispatch(rule)
            if result.triggered:
                self._mark_fired(rule)
            return result
        except Exception as exc:  # noqa: BLE001
            logger.error("Error evaluating rule '%s': %s", rule.id, exc, exc_info=True)
            return AlertResult(
                rule=rule,
                triggered=False,
                current_value=None,
                message=f"ERROR evaluating rule '{rule.id}': {exc}",
            )

    def evaluate_all(self, rules: list[AlertRule]) -> list[AlertResult]:
        """Evaluate all rules and return a list of AlertResults."""
        results = []
        for rule in rules:
            results.append(self.evaluate(rule))
        return results

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, rule: AlertRule) -> AlertResult:
        """Route to the correct evaluator based on rule type."""
        if rule.type == "metric":
            return self._eval_metric(rule)
        elif rule.type == "log_keyword":
            return self._eval_log_keyword(rule)
        elif rule.type == "db_query":
            return self._eval_db_query(rule)
        else:
            return AlertResult(
                rule=rule,
                triggered=False,
                current_value=None,
                message=f"Unknown rule type '{rule.type}'.",
            )

    # ------------------------------------------------------------------
    # Metric evaluation
    # ------------------------------------------------------------------

    def _eval_metric(self, rule: AlertRule) -> AlertResult:
        """Evaluate a CloudWatch metric rule."""
        if self.dry_run:
            # Return a synthetic value that never triggers
            synthetic = 42.0
            triggered = rule.condition.evaluate(synthetic)
            return AlertResult(
                rule=rule,
                triggered=triggered,
                current_value=synthetic,
                message=self._metric_msg(rule, synthetic, triggered),
            )

        # Import lazily to avoid circular imports
        from src.agents.sre_agent import get_metrics

        p = rule.params
        raw = get_metrics(
            namespace=p.get("namespace", "AWS/EC2"),
            metric_name=p.get("metric_name", "CPUUtilization"),
            dimension_name=p.get("dimension_name", "InstanceId"),
            dimension_value=p.get("dimension_value", ""),
            period=int(p.get("period", 300)),
            minutes=int(p.get("minutes", 60)),
        )

        if raw.startswith("ERROR") or raw.startswith("No data"):
            return AlertResult(
                rule=rule,
                triggered=False,
                current_value=None,
                message=f"Metric fetch failed: {raw}",
            )

        datapoints: list[dict[str, Any]] = json.loads(raw)
        if not datapoints:
            return AlertResult(
                rule=rule,
                triggered=False,
                current_value=None,
                message="No metric datapoints returned.",
            )

        # Use the most recent datapoint
        latest = datapoints[-1]
        value = float(latest.get(rule.condition.field, latest.get("avg", 0)))
        triggered = rule.condition.evaluate(value)

        return AlertResult(
            rule=rule,
            triggered=triggered,
            current_value=value,
            message=self._metric_msg(rule, value, triggered),
        )

    def _metric_msg(self, rule: AlertRule, value: float, triggered: bool) -> str:
        status = "🔴 TRIGGERED" if triggered else "✅ OK"
        return (
            f"{status} | {rule.name} | "
            f"{rule.condition.field}={value:.2f} "
            f"(threshold {rule.condition.operator} {rule.condition.threshold})"
        )

    # ------------------------------------------------------------------
    # Log keyword evaluation
    # ------------------------------------------------------------------

    def _eval_log_keyword(self, rule: AlertRule) -> AlertResult:
        """Evaluate a CloudWatch log keyword rule."""
        if self.dry_run:
            count = 0
            triggered = rule.condition.evaluate(count)
            return AlertResult(
                rule=rule,
                triggered=triggered,
                current_value=float(count),
                message=self._keyword_msg(rule, count, triggered),
            )

        from src.agents.sre_agent import fetch_cloudwatch_logs

        p = rule.params
        keyword = p.get("keyword", "ERROR")
        raw = fetch_cloudwatch_logs(
            log_group=p.get("log_group", "/app/prod"),
            log_stream=p.get("log_stream"),
            minutes=int(p.get("minutes", 30)),
            limit=int(p.get("limit", 500)),
        )

        if raw.startswith("ERROR") or raw.startswith("No log"):
            return AlertResult(
                rule=rule,
                triggered=False,
                current_value=None,
                message=f"Log fetch failed: {raw}",
            )

        count = raw.count(keyword)
        triggered = rule.condition.evaluate(float(count))

        return AlertResult(
            rule=rule,
            triggered=triggered,
            current_value=float(count),
            message=self._keyword_msg(rule, count, triggered),
        )

    def _keyword_msg(self, rule: AlertRule, count: int, triggered: bool) -> str:
        status = "🔴 TRIGGERED" if triggered else "✅ OK"
        keyword = rule.params.get("keyword", "ERROR")
        return (
            f"{status} | {rule.name} | "
            f"'{keyword}' occurrences={count} "
            f"(threshold {rule.condition.operator} {rule.condition.threshold})"
        )

    # ------------------------------------------------------------------
    # DB query evaluation
    # ------------------------------------------------------------------

    def _eval_db_query(self, rule: AlertRule) -> AlertResult:
        """Evaluate a database query rule."""
        if self.dry_run:
            value = 100.0
            triggered = rule.condition.evaluate(value)
            return AlertResult(
                rule=rule,
                triggered=triggered,
                current_value=value,
                message=self._query_msg(rule, value, triggered),
            )

        from src.agents.data_agent import run_query

        p = rule.params
        sql = p.get("sql", "SELECT COUNT(*) AS value FROM information_schema.tables")
        value_key = p.get("value_key", "value")

        raw = run_query(sql)
        if raw.startswith("ERROR"):
            return AlertResult(
                rule=rule,
                triggered=False,
                current_value=None,
                message=f"DB query failed: {raw}",
            )

        rows: list[dict] = json.loads(raw)
        if not rows:
            return AlertResult(
                rule=rule,
                triggered=False,
                current_value=None,
                message="DB query returned no rows.",
            )

        try:
            value = float(rows[0][value_key])
        except (KeyError, TypeError, ValueError) as exc:
            return AlertResult(
                rule=rule,
                triggered=False,
                current_value=None,
                message=f"Could not extract '{value_key}' from query result: {exc}",
            )

        triggered = rule.condition.evaluate(value)
        return AlertResult(
            rule=rule,
            triggered=triggered,
            current_value=value,
            message=self._query_msg(rule, value, triggered),
        )

    def _query_msg(self, rule: AlertRule, value: float, triggered: bool) -> str:
        status = "🔴 TRIGGERED" if triggered else "✅ OK"
        return (
            f"{status} | {rule.name} | "
            f"value={value:.2f} "
            f"(threshold {rule.condition.operator} {rule.condition.threshold})"
        )

    # ------------------------------------------------------------------
    # Cooldown helpers
    # ------------------------------------------------------------------

    def _in_cooldown(self, rule: AlertRule) -> bool:
        last = self._cooldown_tracker.get(rule.id)
        if last is None:
            return False
        return (time.time() - last) < (rule.cooldown_minutes * 60)

    def _mark_fired(self, rule: AlertRule) -> None:
        self._cooldown_tracker[rule.id] = time.time()
