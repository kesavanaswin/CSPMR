from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

from utils.models import Alert


class MitigationEngine:
    def __init__(self, alerts_path: str, webhook_path: str):
        self.alerts_path = alerts_path
        self.webhook_path = webhook_path
        os.makedirs(os.path.dirname(alerts_path) or ".", exist_ok=True)

    def process(self, assessment: Any) -> Alert:
        alert = Alert(
            container_id="unknown",
            classification=getattr(assessment, "classification", "Unknown"),
            risk_score=float(getattr(assessment, "normalized_score", 0.0)),
            action_taken="review_container" if getattr(assessment, "classification", "Unknown") in {"High", "Critical"} else "monitor",
            factors=["runtime_security_posture", "policy_evaluation"],
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        try:
            with open(self.alerts_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "container_id": alert.container_id,
                    "classification": alert.classification,
                    "risk_score": alert.risk_score,
                    "action_taken": alert.action_taken,
                    "factors": alert.factors,
                    "timestamp": alert.timestamp,
                }) + "\n")
        except OSError:
            pass
        return alert


class WebhookNotifier:
    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url

    def send(self, alert: Alert | Dict[str, Any]) -> Dict[str, Any]:
        return {"sent": True, "alert": alert, "webhook_url": self.webhook_url}
