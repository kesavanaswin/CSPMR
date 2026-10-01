"""Falco JSON output consumer.

Falco should be configured to emit JSON lines to a file. This collector tails
that file and converts each alert into the CSPM RuntimeEvent model.
"""
from __future__ import annotations
import json
import os
import time
from typing import Iterator

from utils.models import RuntimeEvent


class FalcoStream:
    def __init__(self, path: str, poll_interval: float = 0.25):
        self.path = path
        self.poll_interval = poll_interval

    @staticmethod
    def normalize(raw: dict) -> RuntimeEvent:
        fields = raw.get("output_fields") or {}
        container_id = (
            fields.get("container.id")
            or fields.get("container.name")
            or raw.get("container_id")
            or "unknown"
        )
        detail = raw.get("output") or raw.get("rule") or "Falco event"
        event_type = raw.get("rule") or fields.get("evt.type") or "falco_alert"
        syscall = fields.get("evt.type")
        priority = str(raw.get("priority", "")).upper()
        suspicious = priority in {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING"} or bool(raw.get("rule"))

        return RuntimeEvent(
            container_id=str(container_id),
            event_type=str(event_type),
            detail=str(detail),
            syscall=str(syscall) if syscall else None,
            timestamp=str(raw.get("time") or raw.get("output_fields", {}).get("evt.time") or ""),
            suspicious=suspicious,
        )

    def stream(self) -> Iterator[RuntimeEvent]:
        if not os.path.exists(self.path):
            raise FileNotFoundError(
                f"Falco output file does not exist: {self.path}. "
                "Configure Falco JSON file output first."
            )
        with open(self.path, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(self.poll_interval)
                    continue
                try:
                    yield self.normalize(json.loads(line))
                except json.JSONDecodeError:
                    continue
