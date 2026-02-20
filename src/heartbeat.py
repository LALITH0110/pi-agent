"""
Heartbeat Scheduler (src/heartbeat.py)

Runs the DataGhostAgent on a configurable cron-like interval.
Reads HEARTBEAT_INTERVAL_MINUTES from the environment (default: 60).

Usage (from main.py or standalone):
    from src.heartbeat import Heartbeat
    hb = Heartbeat()
    hb.start()   # blocking — runs forever
"""

from __future__ import annotations

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)


class Heartbeat:
    """Runs the DataGhost agent on a periodic interval.

    Args:
        interval_minutes: How often to fire the agent.
            Reads ``HEARTBEAT_INTERVAL_MINUTES`` env var if not provided.
        task: The task/prompt string to give the agent each cycle.
    """

    DEFAULT_TASK = (
        "Run your standard heartbeat cycle: introspect the schema, "
        "identify the 3 most interesting findings, generate a chart for the top finding, "
        "and write a Markdown report. Be concise."
    )

    def __init__(
        self,
        interval_minutes: int | None = None,
        task: str | None = None,
    ):
        self.interval_minutes = interval_minutes or int(
            os.getenv("HEARTBEAT_INTERVAL_MINUTES", "60")
        )
        self.task = task or self.DEFAULT_TASK
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_cycle(self) -> None:
        """Build a fresh DataGhost engine instance and run one cycle."""
        # Import here to avoid circular imports at module load time
        from src.agents.data_agent import build_data_ghost_agent  # noqa: PLC0415

        logger.info("Heartbeat: starting DataGhost cycle.")
        try:
            engine = build_data_ghost_agent()
            result = engine.run(self.task)
            logger.info("Heartbeat cycle complete.\n%s", result[:500])
        except Exception as exc:  # noqa: BLE001
            logger.error("Heartbeat cycle failed: %s", exc, exc_info=True)

    def _loop(self) -> None:
        """Main loop: run a cycle immediately, then sleep between cycles."""
        logger.info(
            "Heartbeat started. Interval: %d minute(s).", self.interval_minutes
        )
        while not self._stop_event.is_set():
            self._run_cycle()
            # Sleep in small increments so we can respond to stop() promptly
            interval_seconds = self.interval_minutes * 60
            elapsed = 0
            while elapsed < interval_seconds and not self._stop_event.is_set():
                time.sleep(5)
                elapsed += 5
        logger.info("Heartbeat stopped.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, blocking: bool = True) -> None:
        """Start the heartbeat.

        Args:
            blocking: If True, run in the current thread (forever).
                      If False, run in a daemon background thread.
        """
        if blocking:
            self._loop()
        else:
            self._thread = threading.Thread(target=self._loop, daemon=True, name="pi-heartbeat")
            self._thread.start()
            logger.info("Heartbeat running in background thread.")

    def stop(self) -> None:
        """Signal the heartbeat to stop after the current sleep interval."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
