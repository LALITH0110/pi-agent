"""
Alert Notifier (src/monitor/notifier.py)

Delivers AlertResult objects to one or more notification channels:
  - slack   → HTTP POST to SLACK_WEBHOOK_URL
  - email   → SMTP via stdlib smtplib
  - webhook → Generic HTTP POST (JSON) to ALERT_WEBHOOK_URL

Each channel is gated by its env var. Missing config = channel is
skipped with a log warning (never raises).
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import urllib.request
import urllib.error
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.monitor.evaluator import AlertResult

logger = logging.getLogger(__name__)


class AlertNotifier:
    """Sends triggered alert results to configured notification channels.

    Reads all configuration from environment variables at call time
    so that tests can monkeypatch os.environ freely.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(self, result: "AlertResult") -> None:
        """Send an AlertResult to all channels listed in the rule.

        Args:
            result: An AlertResult that has triggered=True.
        """
        if not result.triggered:
            return

        for channel in result.rule.channels:
            try:
                self._dispatch(channel, result)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to send alert '%s' via channel '%s': %s",
                    result.rule.id,
                    channel,
                    exc,
                    exc_info=True,
                )

    def send_all(self, results: list["AlertResult"]) -> None:
        """Send notifications for every triggered result in the list."""
        for result in results:
            self.send(result)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, channel: str, result: "AlertResult") -> None:
        if channel == "slack":
            self._send_slack(result)
        elif channel == "email":
            self._send_email(result)
        elif channel == "webhook":
            self._send_webhook(result)
        else:
            logger.warning("Unknown notification channel: '%s'", channel)

    # ------------------------------------------------------------------
    # Slack
    # ------------------------------------------------------------------

    def _send_slack(self, result: "AlertResult") -> None:
        webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        if not webhook_url:
            logger.warning(
                "SLACK_WEBHOOK_URL not set — skipping Slack alert for '%s'.", result.rule.id
            )
            return

        payload = {
            "text": f"*[Pi-Agent Alert]* {result.message}",
            "attachments": [
                {
                    "color": "#FF0000",
                    "fields": [
                        {"title": "Rule", "value": result.rule.name, "short": True},
                        {"title": "Type", "value": result.rule.type, "short": True},
                        {"title": "Value", "value": str(result.current_value), "short": True},
                        {
                            "title": "Threshold",
                            "value": f"{result.rule.condition.operator} {result.rule.condition.threshold}",
                            "short": True,
                        },
                    ],
                }
            ],
        }
        self._http_post(webhook_url, payload)
        logger.info("Slack alert sent for rule '%s'.", result.rule.id)

    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------

    def _send_email(self, result: "AlertResult") -> None:
        smtp_host = os.getenv("SMTP_HOST", "")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER", "")
        smtp_password = os.getenv("SMTP_PASSWORD", "")
        to_addr = os.getenv("ALERT_EMAIL_TO", "")

        if not all([smtp_host, smtp_user, smtp_password, to_addr]):
            logger.warning(
                "Email config incomplete (need SMTP_HOST, SMTP_USER, SMTP_PASSWORD, "
                "ALERT_EMAIL_TO) — skipping email alert for '%s'.",
                result.rule.id,
            )
            return

        subject = f"[Pi-Agent Alert] {result.rule.name}"
        body = (
            f"Alert: {result.rule.name}\n"
            f"Rule ID: {result.rule.id}\n"
            f"Type: {result.rule.type}\n"
            f"Current value: {result.current_value}\n"
            f"Condition: {result.rule.condition.operator} {result.rule.condition.threshold}\n"
            f"\nMessage:\n{result.message}\n"
        )

        msg = MIMEMultipart()
        msg["From"] = smtp_user
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, to_addr, msg.as_string())

        logger.info("Email alert sent for rule '%s' to '%s'.", result.rule.id, to_addr)

    # ------------------------------------------------------------------
    # Generic webhook
    # ------------------------------------------------------------------

    def _send_webhook(self, result: "AlertResult") -> None:
        webhook_url = os.getenv("ALERT_WEBHOOK_URL", "")
        if not webhook_url:
            logger.warning(
                "ALERT_WEBHOOK_URL not set — skipping webhook alert for '%s'.", result.rule.id
            )
            return

        payload = {
            "rule_id": result.rule.id,
            "rule_name": result.rule.name,
            "rule_type": result.rule.type,
            "triggered": result.triggered,
            "current_value": result.current_value,
            "message": result.message,
            "channels": result.rule.channels,
        }
        self._http_post(webhook_url, payload)
        logger.info("Webhook alert sent for rule '%s'.", result.rule.id)

    # ------------------------------------------------------------------
    # Shared HTTP helper
    # ------------------------------------------------------------------

    def _http_post(self, url: str, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            if status not in (200, 201, 202, 204):
                raise RuntimeError(f"HTTP POST returned status {status}")
