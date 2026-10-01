"""Real webhook notification adapter. Slack-compatible payloads are sent with HTTPS."""
from __future__ import annotations
import os
from typing import Dict
import requests

from utils.models import Alert


class WebhookNotifier:
    def __init__(self, url: str = "", timeout: int = 10):
        self.url = url or os.getenv("CSPM_SLACK_WEBHOOK", "")
        self.timeout = timeout

    def enabled(self) -> bool:
        return bool(self.url)

    def send(self, alert: Alert) -> Dict:
        if not self.url:
            return {"sent": False, "reason": "CSPM_SLACK_WEBHOOK is not configured"}

        payload = {
            "text": (
                f":rotating_light: *{alert.classification} risk detected* "
                f"in `{alert.container_id}`\n"
                f"Score: *{alert.risk_score}/100*\n"
                f"Action: *{alert.action_taken}*\n"
                f"Factors: {', '.join(alert.factors)}"
            ),
            "container_id": alert.container_id,
            "classification": alert.classification,
            "risk_score": alert.risk_score,
            "timestamp": alert.timestamp,
        }
        response = requests.post(self.url, json=payload, timeout=self.timeout)
        response.raise_for_status()
        return {"sent": True, "status_code": response.status_code}
