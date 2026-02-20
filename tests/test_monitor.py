"""
tests/test_monitor.py — Unit tests for the Personalized Monitoring and Alerting subsystem.

All tests are fully self-contained: no real AWS, database, or network calls are made.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.monitor.alert_config import AlertRule, Condition, load_rules
from src.monitor.evaluator import AlertResult, RuleEvaluator
from src.monitor.notifier import AlertNotifier


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_rule(
    rule_id: str = "test-rule",
    rule_type: str = "metric",
    operator: str = "gt",
    threshold: float = 80.0,
    channels: list[str] | None = None,
    cooldown_minutes: int = 0,
    params: dict | None = None,
) -> AlertRule:
    """Build a minimal AlertRule for testing."""
    return AlertRule(
        id=rule_id,
        name=f"Test rule {rule_id}",
        type=rule_type,
        params=params or {},
        condition=Condition(operator=operator, threshold=threshold, field="avg"),
        channels=channels or ["slack"],
        cooldown_minutes=cooldown_minutes,
    )


def _write_rules_file(rules: list[dict]) -> tempfile.NamedTemporaryFile:
    """Write rules to a temp JSON file and return the file object (caller must close)."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(rules, f)
    f.flush()
    return f


# ===========================================================================
# AlertRule / Condition
# ===========================================================================

class TestCondition:
    def test_gt_triggered(self):
        c = Condition(operator="gt", threshold=80.0)
        assert c.evaluate(90.0) is True

    def test_gt_not_triggered(self):
        c = Condition(operator="gt", threshold=80.0)
        assert c.evaluate(70.0) is False

    def test_lt_triggered(self):
        c = Condition(operator="lt", threshold=10.0)
        assert c.evaluate(5.0) is True

    def test_gte_boundary(self):
        c = Condition(operator="gte", threshold=80.0)
        assert c.evaluate(80.0) is True

    def test_lte_boundary(self):
        c = Condition(operator="lte", threshold=80.0)
        assert c.evaluate(80.0) is True

    def test_eq(self):
        c = Condition(operator="eq", threshold=42.0)
        assert c.evaluate(42.0) is True
        assert c.evaluate(43.0) is False

    def test_unknown_operator_returns_false(self):
        c = Condition(operator="unknown", threshold=0.0)
        assert c.evaluate(99.0) is False


class TestAlertRuleFromDict:
    def test_minimal_valid_rule(self):
        rule = AlertRule.from_dict({
            "id": "cpu-high",
            "type": "metric",
            "condition": {"operator": "gt", "threshold": 85},
        })
        assert rule.id == "cpu-high"
        assert rule.type == "metric"
        assert rule.condition.threshold == 85.0
        assert rule.enabled is True

    def test_full_rule(self):
        rule = AlertRule.from_dict({
            "id": "error-spike",
            "name": "Error Spike",
            "type": "log_keyword",
            "enabled": True,
            "params": {"log_group": "/app/prod", "keyword": "ERROR"},
            "condition": {"operator": "gt", "threshold": 10},
            "channels": ["slack", "email"],
            "cooldown_minutes": 15,
        })
        assert rule.name == "Error Spike"
        assert rule.channels == ["slack", "email"]
        assert rule.cooldown_minutes == 15

    def test_disabled_rule_excluded_by_load_rules(self):
        rules_data = [
            {"id": "enabled-rule", "type": "metric", "enabled": True,
             "condition": {"operator": "gt", "threshold": 80}},
            {"id": "disabled-rule", "type": "metric", "enabled": False,
             "condition": {"operator": "gt", "threshold": 80}},
        ]
        f = _write_rules_file(rules_data)
        try:
            rules = load_rules(f.name)
            assert len(rules) == 1
            assert rules[0].id == "enabled-rule"
        finally:
            os.unlink(f.name)

    def test_malformed_rule_skipped(self):
        rules_data = [
            {"id": "good-rule", "type": "metric",
             "condition": {"operator": "gt", "threshold": 80}},
            {"BAD_RULE": True},  # missing required 'id' and 'type'
        ]
        f = _write_rules_file(rules_data)
        try:
            rules = load_rules(f.name)
            assert len(rules) == 1
        finally:
            os.unlink(f.name)

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_rules("/nonexistent/path/alerts.json")

    def test_example_config_loads(self):
        """Verify the shipped example config is valid."""
        example = Path("configs/alerts.example.json")
        if not example.exists():
            pytest.skip("configs/alerts.example.json not found (run from repo root)")
        rules = load_rules(str(example))
        assert len(rules) == 3
        ids = {r.id for r in rules}
        assert "high-cpu" in ids
        assert "error-keyword" in ids
        assert "orders-drop" in ids


# ===========================================================================
# RuleEvaluator — dry_run mode (no real I/O)
# ===========================================================================

class TestRuleEvaluatorDryRun:
    """All evaluator tests run with dry_run=True to avoid real AWS/DB calls."""

    def _evaluator(self):
        return RuleEvaluator(dry_run=True)

    def test_metric_rule_ok(self):
        ev = self._evaluator()
        rule = _make_rule(rule_type="metric", operator="gt", threshold=100.0)
        result = ev.evaluate(rule)
        # dry_run returns synthetic value 42.0; threshold is 100 → not triggered
        assert isinstance(result, AlertResult)
        assert not result.triggered

    def test_metric_rule_triggered(self):
        ev = self._evaluator()
        rule = _make_rule(rule_type="metric", operator="lt", threshold=100.0)
        result = ev.evaluate(rule)
        # dry_run synthetic=42.0 < 100.0 → triggered
        assert result.triggered

    def test_log_keyword_not_triggered(self):
        ev = self._evaluator()
        rule = _make_rule(rule_type="log_keyword", operator="gt", threshold=0.0)
        result = ev.evaluate(rule)
        # dry_run returns count=0; 0 > 0 is False → not triggered
        assert not result.triggered

    def test_db_query_not_triggered(self):
        ev = self._evaluator()
        rule = _make_rule(rule_type="db_query", operator="gt", threshold=200.0)
        result = ev.evaluate(rule)
        # dry_run returns value=100; 100 > 200 is False → not triggered
        assert not result.triggered

    def test_unknown_type_not_triggered(self):
        ev = self._evaluator()
        rule = _make_rule(rule_type="unknown_type")
        result = ev.evaluate(rule)
        assert not result.triggered
        assert "Unknown rule type" in result.message

    def test_evaluate_all_returns_one_per_rule(self):
        ev = self._evaluator()
        rules = [
            _make_rule("r1", "metric"),
            _make_rule("r2", "log_keyword"),
            _make_rule("r3", "db_query"),
        ]
        results = ev.evaluate_all(rules)
        assert len(results) == 3

    def test_cooldown_suppression(self):
        ev = self._evaluator()
        # Use a rule that WILL trigger (lt 100, synthetic=42)
        rule = _make_rule(rule_type="metric", operator="lt", threshold=100.0,
                          cooldown_minutes=60)
        first = ev.evaluate(rule)
        assert first.triggered
        assert not first.suppressed

        # Second call: should be suppressed
        second = ev.evaluate(rule)
        assert not second.triggered
        assert second.suppressed

    def test_cooldown_zero_never_suppresses(self):
        ev = self._evaluator()
        rule = _make_rule(rule_type="metric", operator="lt", threshold=100.0,
                          cooldown_minutes=0)
        first = ev.evaluate(rule)
        assert first.triggered
        second = ev.evaluate(rule)
        # cooldown=0 → 0 minutes window → always fires
        assert second.triggered
        assert not second.suppressed


# ===========================================================================
# RuleEvaluator — live metric/log/db with mocks
# ===========================================================================

class TestRuleEvaluatorMockedSources:
    """Tests with mocked data sources to verify threshold logic."""

    def test_metric_triggers_when_above_threshold(self):
        ev = RuleEvaluator(dry_run=False)
        rule = _make_rule(rule_type="metric", operator="gt", threshold=80.0,
                          params={"metric_name": "CPUUtilization", "minutes": 10, "period": 300})

        fake_data = json.dumps([{"time": "2024-01-01T00:00:00", "avg": 92.5, "max": 95.0}])
        with patch("src.agents.sre_agent.get_metrics", return_value=fake_data):
            result = ev.evaluate(rule)

        assert result.triggered
        assert result.current_value == pytest.approx(92.5)

    def test_metric_ok_when_below_threshold(self):
        ev = RuleEvaluator(dry_run=False)
        rule = _make_rule(rule_type="metric", operator="gt", threshold=80.0,
                          params={"metric_name": "CPUUtilization", "minutes": 10, "period": 300})

        fake_data = json.dumps([{"time": "2024-01-01T00:00:00", "avg": 45.0, "max": 50.0}])
        with patch("src.agents.sre_agent.get_metrics", return_value=fake_data):
            result = ev.evaluate(rule)

        assert not result.triggered

    def test_metric_handles_error_response(self):
        ev = RuleEvaluator(dry_run=False)
        rule = _make_rule(rule_type="metric")
        with patch("src.agents.sre_agent.get_metrics", return_value="ERROR: no credentials"):
            result = ev.evaluate(rule)
        assert not result.triggered
        assert "Metric fetch failed" in result.message

    def test_log_keyword_triggers_on_high_count(self):
        ev = RuleEvaluator(dry_run=False)
        rule = _make_rule(rule_type="log_keyword", operator="gt", threshold=5.0,
                          params={"log_group": "/app/prod", "keyword": "ERROR", "minutes": 15})

        # Prefix lines with a timestamp so they don't start with "ERROR"
        # (the evaluator rejects raw output that starts with "ERROR")
        fake_logs = "\n".join([f"[2024-01-01T00:00:00Z] ERROR something went wrong"] * 10)
        with patch("src.agents.sre_agent.fetch_cloudwatch_logs", return_value=fake_logs):
            result = ev.evaluate(rule)

        assert result.triggered
        assert result.current_value == 10.0

    def test_db_query_triggers_when_below_threshold(self):
        ev = RuleEvaluator(dry_run=False)
        rule = _make_rule(rule_type="db_query", operator="lt", threshold=5.0,
                          params={"sql": "SELECT COUNT(*) AS value FROM orders", "value_key": "value"})

        fake_rows = json.dumps([{"value": 2}])
        with patch("src.agents.data_agent.run_query", return_value=fake_rows):
            result = ev.evaluate(rule)

        assert result.triggered
        assert result.current_value == pytest.approx(2.0)


# ===========================================================================
# AlertNotifier
# ===========================================================================

class TestAlertNotifier:
    """Tests for the multi-channel notifier. No real HTTP/SMTP calls are made."""

    def _triggered_result(self, channels: list[str] | None = None) -> AlertResult:
        rule = _make_rule(channels=channels or ["slack"])
        return AlertResult(
            rule=rule,
            triggered=True,
            current_value=92.5,
            message="🔴 TRIGGERED | Test rule | avg=92.50 (threshold gt 80.0)",
        )

    def _not_triggered_result(self) -> AlertResult:
        rule = _make_rule()
        return AlertResult(rule=rule, triggered=False, current_value=50.0, message="✅ OK")

    # --- send() skips non-triggered results ---

    def test_send_skips_non_triggered(self):
        notifier = AlertNotifier()
        result = self._not_triggered_result()
        # Should not raise; nothing should happen
        notifier.send(result)

    # --- Slack ---

    def test_slack_sends_when_configured(self):
        notifier = AlertNotifier()
        result = self._triggered_result(channels=["slack"])
        with patch.dict(os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/fake"}):
            with patch.object(notifier, "_http_post") as mock_post:
                notifier.send(result)
                mock_post.assert_called_once()
                _, kwargs = mock_post.call_args
                # First positional arg is the URL
                url_arg = mock_post.call_args[0][0]
                assert url_arg == "https://hooks.slack.com/fake"

    def test_slack_skipped_when_not_configured(self, caplog):
        notifier = AlertNotifier()
        result = self._triggered_result(channels=["slack"])
        env_without_slack = {k: v for k, v in os.environ.items() if k != "SLACK_WEBHOOK_URL"}
        with patch.dict(os.environ, env_without_slack, clear=True):
            with patch.object(notifier, "_http_post") as mock_post:
                notifier.send(result)
                mock_post.assert_not_called()

    # --- Webhook ---

    def test_webhook_sends_when_configured(self):
        notifier = AlertNotifier()
        result = self._triggered_result(channels=["webhook"])
        with patch.dict(os.environ, {"ALERT_WEBHOOK_URL": "https://my-webhook.example.com/alert"}):
            with patch.object(notifier, "_http_post") as mock_post:
                notifier.send(result)
                mock_post.assert_called_once()

    def test_webhook_skipped_when_not_configured(self):
        notifier = AlertNotifier()
        result = self._triggered_result(channels=["webhook"])
        env_without_webhook = {k: v for k, v in os.environ.items() if k != "ALERT_WEBHOOK_URL"}
        with patch.dict(os.environ, env_without_webhook, clear=True):
            with patch.object(notifier, "_http_post") as mock_post:
                notifier.send(result)
                mock_post.assert_not_called()

    # --- Email ---

    def test_email_sends_when_configured(self):
        notifier = AlertNotifier()
        result = self._triggered_result(channels=["email"])
        smtp_env = {
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "from@example.com",
            "SMTP_PASSWORD": "secret",
            "ALERT_EMAIL_TO": "oncall@example.com",
        }
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)

        with patch.dict(os.environ, smtp_env):
            with patch("smtplib.SMTP", return_value=mock_smtp):
                notifier.send(result)
                mock_smtp.sendmail.assert_called_once()

    def test_email_skipped_when_not_configured(self):
        notifier = AlertNotifier()
        result = self._triggered_result(channels=["email"])
        # Remove all SMTP env vars
        clean_env = {k: v for k, v in os.environ.items()
                     if k not in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "ALERT_EMAIL_TO")}
        with patch.dict(os.environ, clean_env, clear=True):
            with patch("smtplib.SMTP") as mock_smtp:
                notifier.send(result)
                mock_smtp.assert_not_called()

    def test_unknown_channel_logged_not_raised(self, caplog):
        notifier = AlertNotifier()
        result = self._triggered_result(channels=["pagerduty"])
        notifier.send(result)  # must not raise

    def test_send_all_only_sends_triggered(self):
        notifier = AlertNotifier()
        triggered = self._triggered_result(channels=["slack"])
        not_triggered = self._not_triggered_result()
        with patch.dict(os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/fake"}):
            with patch.object(notifier, "_http_post") as mock_post:
                notifier.send_all([triggered, not_triggered])
                # Only 1 call for the triggered result
                assert mock_post.call_count == 1


# ===========================================================================
# MonitorAgent (lightweight mode)
# ===========================================================================

class TestMonitorAgent:
    def _write_example_rules(self) -> str:
        example = Path("configs/alerts.example.json")
        if example.exists():
            return str(example)
        # Fall back to a temp file with one metric rule
        rules = [{"id": "test-cpu", "type": "metric", "enabled": True,
                   "condition": {"operator": "gt", "threshold": 999}}]
        f = _write_rules_file(rules)
        return f.name

    def test_run_cycle_dry_run(self):
        from src.monitor.monitor_agent import MonitorAgent
        rules_path = self._write_example_rules()
        agent = MonitorAgent(rules_path=rules_path, dry_run=True)
        report = agent.run_cycle()
        assert "Pi-Monitor Cycle Report" in report
        assert "Rules evaluated" in report

    def test_run_cycle_missing_rules_file(self):
        from src.monitor.monitor_agent import MonitorAgent
        agent = MonitorAgent(rules_path="/no/such/file.json", dry_run=True)
        report = agent.run_cycle()
        assert "could not load rules" in report.lower() or "not found" in report.lower()

    def test_run_cycle_no_rules(self):
        from src.monitor.monitor_agent import MonitorAgent
        # Write an empty rules array
        f = _write_rules_file([])
        try:
            agent = MonitorAgent(rules_path=f.name, dry_run=True)
            report = agent.run_cycle()
            assert "no enabled rules" in report.lower()
        finally:
            os.unlink(f.name)


# ===========================================================================
# MonitorHeartbeat lifecycle
# ===========================================================================

class TestMonitorHeartbeat:
    def test_start_stop_non_blocking(self):
        from src.monitor.monitor_heartbeat import MonitorHeartbeat
        from src.monitor.monitor_agent import MonitorAgent

        # Patch run_cycle to avoid real I/O
        with patch.object(MonitorAgent, "run_cycle", return_value="OK"):
            hb = MonitorHeartbeat(
                interval_minutes=60,
                rules_path="configs/alerts.example.json",
                dry_run=True,
            )
            hb.start(blocking=False)
            assert hb._thread is not None
            assert hb._thread.is_alive()
            time.sleep(0.2)
            hb.stop()
            assert hb._stop_event.is_set()
