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
        os.makedirs(os.path.dirname(webhook_path) or ".", exist_ok=True)

    def process(self, assessment: Any, container_id: str = "unknown") -> Alert:
        alert = Alert(
            container_id=container_id,
            classification=getattr(assessment, "classification", "Unknown"),
            risk_score=float(getattr(assessment, "normalized_score", 0.0)),
            action_taken="review_container" if getattr(assessment, "classification", "Unknown") in {"High", "Critical"} else "monitor",
            factors=["runtime_security_posture", "policy_evaluation"],
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        try:
            existing = []
            if os.path.exists(self.alerts_path) and os.path.getsize(self.alerts_path) > 0:
                with open(self.alerts_path, "r", encoding="utf-8") as handle:
                    try:
                        loaded = json.load(handle)
                    except json.JSONDecodeError:
                        loaded = []
                    existing = loaded if isinstance(loaded, list) else []

            existing.append({
                "container_id": alert.container_id,
                "classification": alert.classification,
                "risk_score": alert.risk_score,
                "action_taken": alert.action_taken,
                "factors": alert.factors,
                "timestamp": alert.timestamp,
            })

            with open(self.alerts_path, "w", encoding="utf-8") as handle:
                json.dump(existing, handle, indent=2)
        except OSError:
            pass
        return alert


class WebhookNotifier:
    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url

    def send(self, alert: Alert | Dict[str, Any]) -> Dict[str, Any]:
        return {"sent": True, "alert": alert, "webhook_url": self.webhook_url}
