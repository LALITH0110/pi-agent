# pi-agent

This is an agentic operations framework built on the **Pi engine** (the minimalist core of OpenClaw). It transitions AI from a reactive chatbot into a **proactive team member**—functioning as a self-healing Site Reliability Engineer, a "Data Ghost" analyst, and a **Personalized Monitor**—all governed by a strict, local security sandbox.

This project demonstrates how to build "production-grade" agents where safety and reliability are first-class citizens.

---

## The Four Pillars

### 1. Self-Healing SRE (Cloud Ops)
pi-agent monitors cloud health (e.g., AWS CloudWatch) and autonomously responds to outages.
* **Observe:** Fetches logs and system metrics via `bash` (AWS CLI).
* **Orient:** Analyzes logs to find root causes (OOM errors, 5xx spikes).
* **Act:** Patches scripts using `read`/`edit` or restarts services.
* **Verify:** Performs a post-fix health check before closing the session.

### 2. Proactive "Data Ghost" (Analytics)
An autonomous agent that lives in your database layer and provides insights on a heartbeat cycle.
* **Scheduled Agency:** Uses a cron-like mechanism to trigger investigation.
* **Schema Intelligence:** Automatically detects schema changes and new data patterns.
* **Auto-Reporting:** Generates Markdown summaries and Matplotlib visualizations, delivering them without human intervention.

### 3. Personalized Monitoring & Alerting
A rule-based monitoring layer that continuously evaluates user-defined thresholds and fires targeted alerts.
* **Flexible Rules:** Define `metric` (CloudWatch), `log_keyword`, and `db_query` rules in a simple JSON config (`configs/alerts.json`).
* **Multi-Channel Alerting:** Delivers notifications via **Slack webhook**, **email (SMTP)**, or a **generic HTTP webhook**.
* **Cooldown Suppression:** Each rule has a configurable cooldown window to prevent alert storms.
* **Heartbeat Mode:** Runs on a configurable interval (`MONITOR_INTERVAL_MINUTES`, default 5 min) as a daemon thread.

### 4. The Agent Security Sandbox (Gatekeeper)
A custom extension for the Pi engine that acts as a **Command Interceptor**.
* **Policy-as-Code:** Every `bash` command is scanned against a blacklist and risk-scored.
* **Vulnerability Scanning:** Integrated with `osv-scanner` to prevent the agent from installing vulnerable packages.
* **Safety Rails:** High-risk commands (e.g., `rm`, `delete-db`) are blocked or pushed to a human-in-the-loop Slack channel.

---

## Tech Stack

* **Core Engine:** [Pi](https://github.com/mzechner/openclaw) (Minimalist Agentic Logic)
* **Language:** Python 3.9+
* **Cloud Infrastructure:** AWS (EC2, CloudWatch, RDS)
* **Security Layer:** OSV-Scanner / Open Policy Agent (OPA)
* **Data Layer:** PostgreSQL / SQLAlchemy (SQLite supported for local dev)

---

## Repository Structure

```text
pi-agent/
├── src/
│   ├── core/
│   │   └── engine.py            # Pi-engine orchestration
│   ├── extensions/
│   │   └── sandbox.py           # The Security Interceptor
│   ├── agents/
│   │   ├── sre_agent.py         # SRE prompts and tool-use logic
│   │   └── data_agent.py        # SQL execution and analytics logic
│   ├── monitor/
│   │   ├── alert_config.py      # AlertRule model + JSON loader
│   │   ├── evaluator.py         # Rule evaluator with cooldown suppression
│   │   ├── notifier.py          # Slack / Email / Webhook dispatcher
│   │   ├── monitor_agent.py     # MonitorAgent + Pi engine factory
│   │   └── monitor_heartbeat.py # Periodic monitoring scheduler
│   └── heartbeat.py             # DataGhost cron-based trigger
├── policies/
│   └── security.json            # Rules for blocked/risky commands
├── configs/
│   └── alerts.example.json      # Example alert rules (copy to alerts.json)
├── reports/                     # Auto-generated insights & visualizations
├── tests/                       # pytest test suite
└── main.py                      # Entry point
```

---

## Quick Start

### SRE Agent
```bash
python main.py --mode sre "Investigate the 5xx spike from the last 30 minutes."
```

### Data Ghost (one-shot)
```bash
DATABASE_URL=sqlite:///dev.db python main.py --mode data_ghost
```

### Data Ghost (heartbeat)
```bash
python main.py --mode data_ghost --heartbeat
```

### Monitor — one-shot check
```bash
cp configs/alerts.example.json configs/alerts.json
python main.py --mode monitor --rules configs/alerts.json --dry-run
```

### Monitor — continuous heartbeat
```bash
python main.py --mode monitor --rules configs/alerts.json --heartbeat
```

---

## Alert Rule Format

Create `configs/alerts.json` from the provided example. Each rule specifies a **type**, **params**, **condition**, and **channels**:

```json
{
  "id": "high-cpu",
  "name": "High CPU Utilization",
  "type": "metric",
  "enabled": true,
  "params": {
    "namespace": "AWS/EC2",
    "metric_name": "CPUUtilization",
    "dimension_value": "i-0abc123"
  },
  "condition": { "operator": "gt", "threshold": 85.0, "field": "avg" },
  "channels": ["slack", "email"],
  "cooldown_minutes": 30
}
```

| Field | Options |
|---|---|
| `type` | `metric`, `log_keyword`, `db_query` |
| `condition.operator` | `gt`, `lt`, `gte`, `lte`, `eq` |
| `channels` | `slack`, `email`, `webhook` |

---

## Security Logic: The Interceptor

s-Pi wraps the standard bash execution tool. If the agent attempts a destructive command, the Sandbox intercepts it and returns an error message back to the agent, forcing a different approach.
