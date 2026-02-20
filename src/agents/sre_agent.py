"""
SRE Agent (src/agents/sre_agent.py)

Autonomous Self-Healing SRE that uses the Pi engine to:
  Observe  → Fetch CloudWatch logs & metrics
  Orient   → Analyse root causes (OOM, 5xx spikes, latency)
  Act      → Patch scripts, restart services, edit config files
  Verify   → Health-check the service after remediation
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

import boto3  # type: ignore
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore

from src.core.engine import PiEngine
from src.extensions.sandbox import SecuritySandbox

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System Prompt
# ---------------------------------------------------------------------------

SRE_SYSTEM_PROMPT = """
You are an elite Site Reliability Engineer (SRE) agent named "Pi-SRE".

Your operating mandate follows the OODA loop:
1. OBSERVE  — Fetch the relevant CloudWatch logs and metrics.
2. ORIENT   — Analyse the data to pinpoint the root cause (OOM, 5xx spike, disk full, etc.).
3. ACT      — Take the minimum effective remediation action:
               • Edit faulty config/scripts with `edit_file`.
               • Restart a service with `restart_service`.
               • Scale if needed via bash commands (always use minimal scope).
4. VERIFY   — Run a health check to confirm the service is healthy before closing.

Rules:
- Always explain your reasoning at each OODA step before calling a tool.
- Prefer the least invasive action first.
- Never delete data or drop databases.
- If unsure, escalate by reporting the issue clearly and stopping.
- After verification passes, summarise what you did in a brief incident report.
"""

# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def fetch_cloudwatch_logs(
    log_group: str,
    log_stream: str | None = None,
    minutes: int = 30,
    limit: int = 200,
) -> str:
    """Fetch recent log events from AWS CloudWatch.

    Args:
        log_group: The CloudWatch log group name (e.g. '/app/prod').
        log_stream: Specific stream name. If omitted, fetches the latest stream.
        minutes: How many minutes back to search (default 30).
        limit: Maximum number of log events to return (default 200).

    Returns:
        A newline-separated string of log events, or an error message.
    """
    try:
        client = boto3.client("logs")
        import time
        start_time = int((time.time() - minutes * 60) * 1000)

        if log_stream is None:
            # Find the most recent stream
            resp = client.describe_log_streams(
                logGroupName=log_group,
                orderBy="LastEventTime",
                descending=True,
                limit=1,
            )
            streams = resp.get("logStreams", [])
            if not streams:
                return f"No log streams found in group '{log_group}'."
            log_stream = streams[0]["logStreamName"]

        resp = client.get_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            startTime=start_time,
            limit=limit,
            startFromHead=True,
        )
        events = resp.get("events", [])
        if not events:
            return f"No log events found in {log_group}/{log_stream} for the last {minutes} minutes."

        lines = [e["message"].strip() for e in events]
        return "\n".join(lines)

    except (BotoCoreError, ClientError) as exc:
        return f"ERROR fetching CloudWatch logs: {exc}"


def get_metrics(
    namespace: str = "AWS/EC2",
    metric_name: str = "CPUUtilization",
    dimension_name: str = "InstanceId",
    dimension_value: str = "",
    period: int = 300,
    minutes: int = 60,
) -> str:
    """Fetch a CloudWatch metric's recent data points.

    Args:
        namespace: CloudWatch namespace (e.g. 'AWS/EC2', 'AWS/ApplicationELB').
        metric_name: Metric name (e.g. 'CPUUtilization', 'HTTPCode_Target_5XX_Count').
        dimension_name: Dimension name (e.g. 'InstanceId', 'LoadBalancer').
        dimension_value: Dimension value (e.g. 'i-0abc123').
        period: Data point resolution in seconds (default 300 = 5 min).
        minutes: How many minutes of history to fetch (default 60).

    Returns:
        JSON string of {timestamps, values} or an error message.
    """
    import time as time_mod
    from datetime import datetime, timezone

    try:
        client = boto3.client("cloudwatch")
        end_time = datetime.now(timezone.utc)
        start_time = datetime.fromtimestamp(
            time_mod.time() - minutes * 60, tz=timezone.utc
        )

        kwargs: dict[str, Any] = {
            "Namespace": namespace,
            "MetricName": metric_name,
            "StartTime": start_time,
            "EndTime": end_time,
            "Period": period,
            "Statistics": ["Average", "Maximum"],
        }
        if dimension_value:
            kwargs["Dimensions"] = [{"Name": dimension_name, "Value": dimension_value}]

        resp = client.get_metric_statistics(**kwargs)
        datapoints = sorted(resp.get("Datapoints", []), key=lambda d: d["Timestamp"])

        if not datapoints:
            return f"No data for metric '{metric_name}' in the last {minutes} minutes."

        result = [
            {
                "time": dp["Timestamp"].isoformat(),
                "avg": round(dp["Average"], 2),
                "max": round(dp["Maximum"], 2),
            }
            for dp in datapoints
        ]
        return json.dumps(result, indent=2)

    except (BotoCoreError, ClientError) as exc:
        return f"ERROR fetching CloudWatch metric: {exc}"


def read_file(path: str) -> str:
    """Read and return the contents of a file.

    Args:
        path: Absolute or relative path to the file.

    Returns:
        File contents as a string, or an error message.
    """
    try:
        return Path(path).read_text()
    except OSError as exc:
        return f"ERROR reading file '{path}': {exc}"


def edit_file(path: str, old_text: str, new_text: str) -> str:
    """Replace a specific string inside a file (surgical edit).

    Args:
        path: Path to the file to edit.
        old_text: Exact string to find and replace.
        new_text: Replacement string.

    Returns:
        Success message, or an error if the text was not found.
    """
    try:
        content = Path(path).read_text()
        if old_text not in content:
            return f"ERROR: Text not found in '{path}'. No changes made."
        new_content = content.replace(old_text, new_text, 1)
        Path(path).write_text(new_content)
        return f"OK: Edited '{path}' successfully."
    except OSError as exc:
        return f"ERROR editing file '{path}': {exc}"


def restart_service(service_name: str) -> str:
    """Restart a systemd service.

    Args:
        service_name: Name of the service (e.g. 'nginx', 'gunicorn').

    Returns:
        Output of systemctl restart, or an error message.
    """
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "restart", service_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return f"OK: Service '{service_name}' restarted successfully."
        return f"ERROR restarting '{service_name}': {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return f"ERROR: Restart of '{service_name}' timed out."
    except OSError as exc:
        return f"ERROR: {exc}"


def run_health_check(url: str, timeout: int = 10) -> str:
    """Perform an HTTP GET health check against a URL.

    Args:
        url: The endpoint to check (e.g. 'http://localhost:8000/health').
        timeout: Request timeout in seconds (default 10).

    Returns:
        HTTP status code and response snippet, or an error message.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read(200).decode("utf-8", errors="replace")
            return f"OK: {resp.status} — {body[:100]}"
    except Exception as exc:  # noqa: BLE001
        return f"UNHEALTHY: {exc}"


# ---------------------------------------------------------------------------
# Tool Schemas
# ---------------------------------------------------------------------------

_TOOL_SCHEMAS = {
    "fetch_cloudwatch_logs": {
        "type": "object",
        "properties": {
            "log_group": {"type": "string", "description": "CloudWatch log group name"},
            "log_stream": {"type": "string", "description": "Log stream name (optional, uses latest if omitted)"},
            "minutes": {"type": "integer", "description": "Minutes of history to fetch (default 30)"},
            "limit": {"type": "integer", "description": "Max number of log events to return (default 200)"},
        },
        "required": ["log_group"],
    },
    "get_metrics": {
        "type": "object",
        "properties": {
            "namespace": {"type": "string", "description": "CloudWatch namespace"},
            "metric_name": {"type": "string", "description": "Metric name"},
            "dimension_name": {"type": "string", "description": "Dimension key"},
            "dimension_value": {"type": "string", "description": "Dimension value"},
            "period": {"type": "integer", "description": "Resolution in seconds (default 300)"},
            "minutes": {"type": "integer", "description": "Minutes of history (default 60)"},
        },
        "required": ["metric_name"],
    },
    "read_file": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the file"},
        },
        "required": ["path"],
    },
    "edit_file": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the file"},
            "old_text": {"type": "string", "description": "Exact text to replace"},
            "new_text": {"type": "string", "description": "Replacement text"},
        },
        "required": ["path", "old_text", "new_text"],
    },
    "restart_service": {
        "type": "object",
        "properties": {
            "service_name": {"type": "string", "description": "systemd service name"},
        },
        "required": ["service_name"],
    },
    "run_health_check": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "HTTP(S) URL to health-check"},
            "timeout": {"type": "integer", "description": "Request timeout in seconds (default 10)"},
        },
        "required": ["url"],
    },
}

# ---------------------------------------------------------------------------
# SREAgent factory
# ---------------------------------------------------------------------------

def build_sre_agent(
    policy_path: str = "policies/security.json",
    model: str = "gpt-4o",
) -> PiEngine:
    """Build and return a fully-wired SRE PiEngine instance.

    Args:
        policy_path: Path to the security policy JSON.
        model: OpenAI model to use.

    Returns:
        Configured PiEngine ready to call `.run(task)`.
    """
    engine = PiEngine(system_prompt=SRE_SYSTEM_PROMPT, model=model)
    sandbox = SecuritySandbox(policy_path=policy_path)
    engine.add_interceptor(sandbox)

    tool_map = {
        "fetch_cloudwatch_logs": (fetch_cloudwatch_logs, "Fetch recent log events from a CloudWatch log group/stream"),
        "get_metrics": (get_metrics, "Fetch a CloudWatch metric's recent data points"),
        "read_file": (read_file, "Read the contents of a file on the local filesystem"),
        "edit_file": (edit_file, "Surgically replace a string inside a file"),
        "restart_service": (restart_service, "Restart a systemd service"),
        "run_health_check": (run_health_check, "HTTP GET health check against a URL"),
    }

    for name, (fn, desc) in tool_map.items():
        engine.registry.register(fn, name=name, description=desc, parameters=_TOOL_SCHEMAS[name])

    return engine
