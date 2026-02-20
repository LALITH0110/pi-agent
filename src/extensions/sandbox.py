"""
Security Sandbox (src/extensions/sandbox.py)

Wraps bash command execution with:
  1. Blacklist: fully blocks destructive commands.
  2. Risk Scorer: assigns a 0–100 risk score to risky commands.
  3. High-risk escalation: POSTs to a Slack webhook for human approval.
  4. OSV-Scanner: checks for known vulnerabilities before any `pip install`.

Integrates with PiEngine as a ToolInterceptor.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

import requests  # type: ignore

from src.core.engine import BlockedCommandError, ToolInterceptor

logger = logging.getLogger(__name__)

_BASH_TOOL_NAMES = {"bash", "run_bash", "shell", "execute_bash", "execute_command"}


class SecuritySandbox(ToolInterceptor):
    """Command Interceptor that enforces the security policy defined in policies/security.json.

    Args:
        policy_path: Path to the security policy JSON file.
        risk_threshold: Commands scoring >= this trigger Slack escalation.
        slack_webhook_url: Slack incoming webhook URL. Reads ``SLACK_WEBHOOK_URL`` env var if not provided.
        osv_enabled: Whether to run ``osv-scanner`` before pip installs.
    """

    def __init__(
        self,
        policy_path: str | Path = "policies/security.json",
        risk_threshold: int | None = None,
        slack_webhook_url: str | None = None,
        osv_enabled: bool | None = None,
    ):
        self.policy_path = Path(policy_path)
        self.risk_threshold = risk_threshold or int(
            os.getenv("RISK_SCORE_THRESHOLD", "70")
        )
        self.slack_webhook_url = slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")
        osv_env = os.getenv("OSV_SCANNER_ENABLED", "true").lower()
        self.osv_enabled = osv_enabled if osv_enabled is not None else (osv_env == "true")

        self._policy = self._load_policy()
        logger.info(
            "SecuritySandbox loaded: %d blocked patterns, %d risky patterns, threshold=%d",
            len(self._policy["blocked"]),
            len(self._policy["risky"]),
            self.risk_threshold,
        )

    # ------------------------------------------------------------------
    # Policy loading
    # ------------------------------------------------------------------

    def _load_policy(self) -> dict:
        if not self.policy_path.exists():
            logger.warning("Policy file not found at '%s'. Using empty policy.", self.policy_path)
            return {"blocked": [], "risky": {}, "allowed_services": []}
        with self.policy_path.open() as f:
            return json.load(f)

    # ------------------------------------------------------------------
    # ToolInterceptor overrides
    # ------------------------------------------------------------------

    def before_call(self, tool_name: str, arguments: dict) -> dict:
        """Intercept bash-like tool calls and enforce the security policy."""
        if tool_name not in _BASH_TOOL_NAMES:
            return arguments  # Not a bash tool — pass through unchanged

        command = arguments.get("command", arguments.get("cmd", ""))
        if not command:
            return arguments

        logger.debug("Sandbox intercepting command: %s", command[:200])

        # 1. Block check
        self._check_blocked(command)

        # 2. Risk score
        score = self._risk_score(command)
        if score > 0:
            logger.warning("Command risk score: %d — '%s'", score, command[:120])

        # 3. OSV scan for pip installs
        if self.osv_enabled and ("pip install" in command or "pip3 install" in command):
            self._osv_check(command)

        # 4. Slack escalation for high-risk commands
        if score >= self.risk_threshold:
            self._escalate_to_slack(command, score)
            raise BlockedCommandError(
                f"BLOCKED (risk score {score} ≥ threshold {self.risk_threshold}): "
                f"Command sent to Slack for human approval. Command: {command}"
            )

        return arguments

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_blocked(self, command: str) -> None:
        """Raise BlockedCommandError if the command matches any blocked pattern."""
        cmd_lower = command.lower()
        for pattern in self._policy.get("blocked", []):
            if pattern.lower() in cmd_lower:
                raise BlockedCommandError(
                    f"BLOCKED: Command matches blocked pattern '{pattern}'. Refusing to execute."
                )

    def _risk_score(self, command: str) -> int:
        """Return the highest risk score for any risky pattern found in the command."""
        cmd_lower = command.lower()
        max_score = 0
        for pattern, score in self._policy.get("risky", {}).items():
            if pattern.lower() in cmd_lower:
                max_score = max(max_score, score)
        return max_score

    def _osv_check(self, command: str) -> None:
        """Run osv-scanner against any packages being pip-installed.

        If osv-scanner is not installed, logs a warning and continues.
        If vulnerabilities are found, raises BlockedCommandError.
        """
        # Extract package name(s) from the command (naive but effective for common patterns)
        packages = []
        for part in command.split():
            if not part.startswith("-") and part not in ("pip", "pip3", "install"):
                packages.append(part)

        if not packages:
            return

        try:
            for pkg in packages:
                logger.info("OSV-scanning package: %s", pkg)
                result = subprocess.run(
                    ["osv-scanner", "--package", pkg],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0 and "VULNERABILITY" in result.stdout.upper():
                    raise BlockedCommandError(
                        f"BLOCKED: osv-scanner detected vulnerabilities in package '{pkg}'.\n"
                        f"Details:\n{result.stdout}"
                    )
        except FileNotFoundError:
            logger.warning(
                "osv-scanner not found on PATH. Skipping vulnerability check. "
                "Install with: brew install osv-scanner"
            )

    def _escalate_to_slack(self, command: str, score: int) -> None:
        """POST a warning to Slack so a human can review the high-risk command."""
        if not self.slack_webhook_url:
            logger.warning(
                "No SLACK_WEBHOOK_URL set. Cannot escalate high-risk command (score=%d): %s",
                score,
                command[:200],
            )
            return

        payload = {
            "text": (
                f":rotating_light: *pi-agent Security Alert* :rotating_light:\n"
                f"*Risk Score:* {score}/{self.risk_threshold} (threshold)\n"
                f"*Command blocked pending review:*\n```{command}```\n"
                f"Please review and approve/deny manually."
            )
        }
        try:
            resp = requests.post(self.slack_webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info("Escalation sent to Slack (score=%d).", score)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to send Slack escalation: %s", exc)

    # ------------------------------------------------------------------
    # Convenience: direct interception (useful in tests / REPL)
    # ------------------------------------------------------------------

    def intercept(self, command: str) -> str:
        """Directly evaluate a raw command string. Returns 'OK' or a block message.

        This is the public API used in smoke-tests where you don't go through
        the engine's tool dispatch.
        """
        try:
            self.before_call("bash", {"command": command})
            score = self._risk_score(command)
            if score > 0:
                return f"WARNING (risk score {score}): Command is risky but below block threshold."
            return "OK: Command passed all security checks."
        except BlockedCommandError as exc:
            return str(exc)
