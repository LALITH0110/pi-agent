#!/usr/bin/env python3
"""
main.py — pi-agent entry point

Usage:
  python main.py --mode sre   "Investigate the 5xx spike from the last 30 minutes."
  python main.py --mode data_ghost
  python main.py --mode data_ghost --heartbeat          # Run continuously on a schedule
  python main.py --mode monitor --rules configs/alerts.json
  python main.py --mode monitor --rules configs/alerts.json --heartbeat
  python main.py --mode monitor --rules configs/alerts.json --dry-run
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("pi-agent")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pi-agent",
        description="Agentic operations framework — SRE & Data Ghost modes.",
    )
    parser.add_argument(
        "--mode",
        choices=["sre", "data_ghost", "monitor"],
        required=True,
        help="Which agent to run: 'sre', 'data_ghost', or 'monitor'.",
    )
    parser.add_argument(
        "--heartbeat",
        action="store_true",
        default=False,
        help="Run on a recurring schedule instead of once (data_ghost and monitor modes).",
    )
    parser.add_argument(
        "--rules",
        default="configs/alerts.json",
        help="(monitor only) Path to the alert rules JSON config (default: configs/alerts.json).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="(monitor only) Evaluate rules but skip real AWS/DB/notification calls.",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o",
        help="OpenAI model to use (default: gpt-4o).",
    )
    parser.add_argument(
        "--policy",
        default="policies/security.json",
        help="Path to the security policy JSON (default: policies/security.json).",
    )
    parser.add_argument(
        "task",
        nargs="?",
        default=None,
        help="Task description to pass to the agent (SRE mode or one-shot data_ghost).",
    )
    return parser


# ---------------------------------------------------------------------------
# Runners
# ---------------------------------------------------------------------------

def run_sre(task: str, model: str, policy: str) -> None:
    from src.agents.sre_agent import build_sre_agent  # noqa: PLC0415

    if not task:
        logger.error("SRE mode requires a task description. Example:\n"
                     "  python main.py --mode sre \"Investigate the 5xx spike.\"")
        sys.exit(1)

    logger.info("Starting SRE agent. Task: %s", task)
    engine = build_sre_agent(policy_path=policy, model=model)
    result = engine.run(task)
    print("\n" + "=" * 60)
    print("SRE AGENT RESPONSE")
    print("=" * 60)
    print(result)


def run_data_ghost_once(task: str | None, model: str, policy: str) -> None:
    from src.agents.data_agent import build_data_ghost_agent  # noqa: PLC0415

    default_task = (
        "Run your standard analysis cycle: introspect the schema, identify the 3 most "
        "interesting findings, generate a chart for the top finding, and write a Markdown report."
    )
    task = task or default_task

    logger.info("Starting DataGhost agent (one-shot). Task: %s", task[:80])
    engine = build_data_ghost_agent(policy_path=policy, model=model)
    result = engine.run(task)
    print("\n" + "=" * 60)
    print("DATA GHOST REPORT")
    print("=" * 60)
    print(result)


def run_data_ghost_heartbeat(task: str | None, model: str, policy: str) -> None:
    from src.heartbeat import Heartbeat  # noqa: PLC0415

    logger.info("Starting DataGhost in heartbeat mode.")
    hb = Heartbeat(task=task)
    try:
        hb.start(blocking=True)
    except KeyboardInterrupt:
        logger.info("Heartbeat interrupted. Shutting down.")
        hb.stop()


def run_monitor_once(rules: str, dry_run: bool) -> None:
    from src.monitor.monitor_agent import MonitorAgent  # noqa: PLC0415

    logger.info("Starting Monitor agent (one-shot). Rules: %s", rules)
    agent = MonitorAgent(rules_path=rules, dry_run=dry_run)
    result = agent.run_cycle()
    print("\n" + "=" * 60)
    print("MONITOR CYCLE REPORT")
    print("=" * 60)
    print(result)


def run_monitor_heartbeat(rules: str, dry_run: bool) -> None:
    from src.monitor.monitor_heartbeat import MonitorHeartbeat  # noqa: PLC0415

    logger.info("Starting MonitorHeartbeat. Rules: %s", rules)
    hb = MonitorHeartbeat(rules_path=rules, dry_run=dry_run)
    try:
        hb.start(blocking=True)
    except KeyboardInterrupt:
        logger.info("MonitorHeartbeat interrupted. Shutting down.")
        hb.stop()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not os.getenv("OPENAI_API_KEY"):
        logger.error("OPENAI_API_KEY is not set. Add it to your .env file.")
        sys.exit(1)

    if args.mode == "sre":
        run_sre(args.task, args.model, args.policy)
    elif args.mode == "data_ghost":
        if args.heartbeat:
            run_data_ghost_heartbeat(args.task, args.model, args.policy)
        else:
            run_data_ghost_once(args.task, args.model, args.policy)
    elif args.mode == "monitor":
        if args.heartbeat:
            run_monitor_heartbeat(args.rules, args.dry_run)
        else:
            run_monitor_once(args.rules, args.dry_run)


if __name__ == "__main__":
    main()
