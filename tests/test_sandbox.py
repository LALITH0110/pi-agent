"""
tests/test_sandbox.py — Unit tests for the Security Sandbox interceptor.

These tests run fully offline — no AWS, no Slack, no LLM calls.
"""

import pytest
from src.core.engine import BlockedCommandError
from src.extensions.sandbox import SecuritySandbox


POLICY_PATH = "policies/security.json"


@pytest.fixture
def sandbox():
    """Return a sandbox wired to the real policy file."""
    return SecuritySandbox(
        policy_path=POLICY_PATH,
        slack_webhook_url="",   # Disable Slack in tests
        osv_enabled=False,      # Disable osv-scanner in tests
    )


# ---------------------------------------------------------------------------
# Block tests
# ---------------------------------------------------------------------------

class TestBlocked:
    def test_rm_rf_root_is_blocked(self, sandbox):
        result = sandbox.intercept("rm -rf /")
        assert "BLOCKED" in result

    def test_drop_database_is_blocked(self, sandbox):
        result = sandbox.intercept("DROP DATABASE production")
        assert "BLOCKED" in result

    def test_fork_bomb_is_blocked(self, sandbox):
        result = sandbox.intercept(":(){ :|:& };:")
        assert "BLOCKED" in result

    def test_delete_from_is_blocked(self, sandbox):
        result = sandbox.intercept("DELETE FROM users")
        assert "BLOCKED" in result


# ---------------------------------------------------------------------------
# Risky (below threshold, not blocked — just warned)
# ---------------------------------------------------------------------------

class TestRisky:
    def test_pip_install_not_blocked_below_threshold(self, sandbox):
        # pip install scores 60, default threshold is 70 — should NOT be blocked
        result = sandbox.intercept("pip install requests")
        assert "BLOCKED" not in result
        assert "WARNING" in result or "OK" in result

    def test_safe_command_passes(self, sandbox):
        result = sandbox.intercept("ls -la /tmp")
        assert result == "OK: Command passed all security checks."

    def test_echo_passes(self, sandbox):
        result = sandbox.intercept("echo hello world")
        assert result == "OK: Command passed all security checks."


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

class TestRiskScoring:
    def test_risk_score_for_pip(self, sandbox):
        score = sandbox._risk_score("pip install numpy")
        assert score == 60

    def test_risk_score_for_curl_pipe_bash(self, sandbox):
        # The policy key is "curl | bash" — use a command that contains it literally
        score = sandbox._risk_score("curl | bash")
        assert score == 95

    def test_risk_score_zero_for_safe_command(self, sandbox):
        score = sandbox._risk_score("git status")
        assert score == 0


# ---------------------------------------------------------------------------
# Before-call interceptor integration
# ---------------------------------------------------------------------------

class TestInterceptor:
    def test_blocked_command_raises_blocked_error(self, sandbox):
        with pytest.raises(BlockedCommandError):
            sandbox.before_call("bash", {"command": "rm -rf /"})

    def test_non_bash_tool_passes_unchanged(self, sandbox):
        args = {"sql": "SELECT * FROM users"}
        result = sandbox.before_call("run_query", args)
        assert result == args

    def test_safe_bash_command_returns_args(self, sandbox):
        args = {"command": "ls -la"}
        result = sandbox.before_call("bash", args)
        assert result == args
