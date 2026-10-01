from __future__ import annotations

import os
from collections import defaultdict
from typing import Any, Dict, Iterable, List

try:
    import yaml
except Exception:  # pragma: no cover - yaml is optional in lightweight fallbacks.
    yaml = None


class PolicyEngine:
    """Minimal policy engine representing the workflow expected by the realtime code."""

    def __init__(self, policy_path: str):
        self.policy_path = policy_path
        self.environment_multipliers = {
            "development": 0.8,
            "staging": 1.0,
            "production": 1.3,
        }
        self._checks = self._load_policy(policy_path)

    def _load_policy(self, policy_path: str) -> Dict[str, Any]:
        default = {
            "environment_multipliers": self.environment_multipliers,
            "checks": {
                "privileged": {"enabled": True, "severity": "high"},
                "host_network": {"enabled": True, "severity": "medium"},
                "host_pid": {"enabled": True, "severity": "medium"},
                "run_as_root": {"enabled": True, "severity": "medium"},
                "exposed_publicly": {"enabled": True, "severity": "medium"},
            },
        }
        if not policy_path or not os.path.exists(policy_path):
            return default

        try:
            if yaml is not None:
                with open(policy_path, "r", encoding="utf-8") as handle:
                    data = yaml.safe_load(handle) or {}
                if isinstance(data, dict):
                    default.update(data)
                    self.environment_multipliers = default.get("environment_multipliers", self.environment_multipliers)
                    return default
        except Exception:
            pass
        return default

    def evaluate(self, container) -> List[Dict[str, Any]]:
        if container is None:
            return []

        findings: List[Dict[str, Any]] = []
        if getattr(container, "privileged", False):
            findings.append({"id": "privileged", "severity": "high", "message": "Container runs privileged"})
        if getattr(container, "host_network", False):
            findings.append({"id": "host_network", "severity": "medium", "message": "Container uses host networking"})
        if getattr(container, "host_pid", False):
            findings.append({"id": "host_pid", "severity": "medium", "message": "Container shares host PID namespace"})
        if getattr(container, "run_as_root", False):
            findings.append({"id": "run_as_root", "severity": "medium", "message": "Container runs as root"})
        if getattr(container, "exposed_publicly", False):
            findings.append({"id": "exposed_publicly", "severity": "medium", "message": "Container exposes a public port"})
        return findings


class AnomalyDetector:
    def __init__(self, contamination: float = 0.25):
        self.contamination = contamination

    def analyze(self, events: Iterable[Any]) -> Dict[str, float]:
        scores: Dict[str, float] = defaultdict(float)
        for event in events:
            cid = str(getattr(event, "container_id", "") or "").strip()
            if not cid or cid == "unknown":
                continue
            if getattr(event, "suspicious", False):
                scores[cid] += 25.0
            else:
                scores[cid] += 5.0
        return dict(scores)
