# pi-agent

This is an agentic operations framework built on the **Pi engine** (the minimalist core of OpenClaw). It transitions AI from a reactive chatbot into a **proactive team member**—functioning as a self-healing Site Reliability Engineer and a "Data Ghost" analyst, all while governed by a strict, local security sandbox.

This project demonstrates how to build "production-grade" agents where safety and reliability are first-class citizens.

---

## The Three Pillars

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

### 3. The agent Security Sandbox (Gatekeeper)
A custom extension for the Pi engine that acts as a **Command Interceptor**.
* **Policy-as-Code:** Every `bash` command is scanned against a blacklist and risk-scored.
* **Vulnerability Scanning:** Integrated with `osv-scanner` to prevent the agent from installing vulnerable packages.
* **Safety Rails:** High-risk commands (e.g., `rm`, `delete-db`) are blocked or pushed to a human-in-the-loop Slack channel.

---

## Tech Stack

* **Core Engine:** [Pi](https://github.com/mzechner/openclaw) (Minimalist Agentic Logic)
* **Language:** Python 3.12+
* **Cloud Infrastructure:** AWS (EC2, CloudWatch, RDS)
* **Security Layer:** OSV-Scanner / Open Policy Agent (OPA)
* **Data Layer:** PostgreSQL / SQL Alchemy

---

## Repository Structure

```text
pi/
├── src/
│   ├── core/
│   │   └── engine.py        # Pi-engine orchestration
│   ├── extensions/
│   │   └── sandbox.py       # The Security Interceptor 
│   ├── agents/
│   │   ├── sre_agent.py     # SRE prompts and tool-use logic
│   │   └── data_agent.py    # SQL execution and analytics logic
│   └── heartbeat.py         # Cron-based trigger system
├── policies/
│   └── security.json        # Rules for blocked/risky commands
├── reports/                 # Auto-generated insights & visualizations
└── main.py                  # Entry point
```

## Security Logic: The Interceptor

s-Pi wraps the standard bash execution tool. If the agent attempts a destructive command, the Sandbox intercepts it and returns an error message back to the agent, forcing a different approach.
