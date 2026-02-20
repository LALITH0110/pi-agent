"""
Monitor Heartbeat (src/monitor/monitor_heartbeat.py)

Runs the MonitorAgent on a periodic interval, identical in structure
to src/heartbeat.py (the DataGhost heartbeat).

Reads MONITOR_INTERVAL_MINUTES from the environment (default: 5).

Usage:
    from src.monitor.monitor_heartbeat import MonitorHeartbeat
    hb = MonitorHeartbeat(rules_path="configs/alerts.json")
    hb.start()   # blocking — runs forever

    # Or non-blocking:
    hb.start(blocking=False)
    # ... later ...
    hb.stop()
"""

from __future__ import annotations

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)


class MonitorHeartbeat:
    """Runs the MonitorAgent on a periodic interval.

    Args:
        interval_minutes: How often to fire a monitoring cycle.
            Reads ``MONITOR_INTERVAL_MINUTES`` env var if not provided.
        rules_path: Path to the JSON alert rules config.
            Reads ``ALERT_RULES_PATH`` env var if not provided.
        dry_run: If True, no real AWS/DB/notification calls are made.
    """

    def __init__(
        self,
        interval_minutes: int | None = None,
        rules_path: str | None = None,
        dry_run: bool = False,
    ):
        self.interval_minutes = interval_minutes or int(
            os.getenv("MONITOR_INTERVAL_MINUTES", "5")
        )
        self.rules_path = rules_path or os.getenv("ALERT_RULES_PATH", "configs/alerts.json")
        self.dry_run = dry_run
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_cycle(self) -> None:
        """Build a fresh MonitorAgent and run one monitoring cycle."""
        from src.monitor.monitor_agent import MonitorAgent  # lazy import

        logger.info("MonitorHeartbeat: starting cycle.")
        try:
            agent = MonitorAgent(rules_path=self.rules_path, dry_run=self.dry_run)
            result = agent.run_cycle()
            logger.info("MonitorHeartbeat cycle complete.\n%s", result[:800])
        except Exception as exc:  # noqa: BLE001
            logger.error("MonitorHeartbeat cycle failed: %s", exc, exc_info=True)

    def _loop(self) -> None:
        """Main loop: run a cycle immediately, then sleep between cycles."""
        logger.info(
            "MonitorHeartbeat started. Interval: %d minute(s). Rules: %s.",
            self.interval_minutes,
            self.rules_path,
        )
        while not self._stop_event.is_set():
            self._run_cycle()
            interval_seconds = self.interval_minutes * 60
            elapsed = 0
            while elapsed < interval_seconds and not self._stop_event.is_set():
                time.sleep(5)
                elapsed += 5
        logger.info("MonitorHeartbeat stopped.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, blocking: bool = True) -> None:
        """Start the monitor heartbeat.

        Args:
            blocking: If True, run in the current thread (forever).
                      If False, run in a daemon background thread.
        """
        if blocking:
            self._loop()
        else:
            self._thread = threading.Thread(
                target=self._loop, daemon=True, name="pi-monitor-heartbeat"
            )
            self._thread.start()
            logger.info("MonitorHeartbeat running in background thread.")

    def stop(self) -> None:
        """Signal the heartbeat to stop after the current sleep interval."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
