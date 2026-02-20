"""
Alert Configuration (src/monitor/alert_config.py)

Defines the AlertRule dataclass and load_rules() loader.
Rules are stored in a JSON config file (e.g. configs/alerts.json).

Rule shape:
{
    "id": "high-cpu",
    "name": "High CPU Utilization",
    "type": "metric",          # metric | log_keyword | db_query
    "enabled": true,
    "params": { ... },         # type-specific fetch parameters
    "condition": {
        "operator": "gt",      # gt | lt | gte | lte | eq | contains
        "threshold": 85.0,
        "field": "avg"         # for metric rules: avg | max; unused for others
    },
    "channels": ["slack", "email"],   # slack | email | webhook
    "cooldown_minutes": 30
}
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Condition
# ---------------------------------------------------------------------------

@dataclass
class Condition:
    """Describes when an alert should fire."""
    operator: str          # gt, lt, gte, lte, eq, contains
    threshold: float       # numeric threshold (or keyword occurrence count)
    field: str = "avg"     # for metric rules: avg | max

    def evaluate(self, value: float) -> bool:
        """Return True if `value` satisfies this condition."""
        if self.operator == "gt":
            return value > self.threshold
        elif self.operator == "lt":
            return value < self.threshold
        elif self.operator == "gte":
            return value >= self.threshold
        elif self.operator == "lte":
            return value <= self.threshold
        elif self.operator == "eq":
            return value == self.threshold
        else:
            logger.warning("Unknown operator '%s'; defaulting to False.", self.operator)
            return False


# ---------------------------------------------------------------------------
# AlertRule
# ---------------------------------------------------------------------------

@dataclass
class AlertRule:
    """A single user-defined monitoring rule."""
    id: str
    name: str
    type: str              # metric | log_keyword | db_query
    params: dict[str, Any]
    condition: Condition
    channels: list[str] = field(default_factory=list)
    cooldown_minutes: int = 30
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "AlertRule":
        """Construct an AlertRule from a raw config dict."""
        cond_raw = data.get("condition", {})
        condition = Condition(
            operator=cond_raw.get("operator", "gt"),
            threshold=float(cond_raw.get("threshold", 0)),
            field=cond_raw.get("field", "avg"),
        )
        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            type=data["type"],
            params=data.get("params", {}),
            condition=condition,
            channels=data.get("channels", ["slack"]),
            cooldown_minutes=int(data.get("cooldown_minutes", 30)),
            enabled=bool(data.get("enabled", True)),
        )


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_rules(path: str = "configs/alerts.json") -> list[AlertRule]:
    """Load and parse alert rules from a JSON config file.

    Args:
        path: Path to the alerts JSON file.

    Returns:
        List of AlertRule objects. Only enabled rules are returned.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the JSON is malformed or a rule is missing required keys.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(
            f"Alert rules config not found: '{path}'. "
            "Create one from configs/alerts.example.json."
        )

    raw = json.loads(config_path.read_text())
    rules_raw: list[dict] = raw if isinstance(raw, list) else raw.get("rules", [])

    rules: list[AlertRule] = []
    for i, entry in enumerate(rules_raw):
        try:
            rule = AlertRule.from_dict(entry)
            if rule.enabled:
                rules.append(rule)
            else:
                logger.debug("Skipping disabled rule: %s", entry.get("id", f"[{i}]"))
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("Skipping malformed rule at index %d: %s", i, exc)

    logger.info("Loaded %d enabled rule(s) from '%s'.", len(rules), path)
    return rules
