from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class Assessment:
    classification: str
    normalized_score: float
    vulnerability_score: float = 0.0
    privilege_score: float = 0.0
    exposure_score: float = 0.0
    anomaly_score: float = 0.0


class RiskEngine:
    def __init__(self, environment_multipliers: Optional[Dict[str, float]] = None):
        self.environment_multipliers = environment_multipliers or {
            "development": 0.8,
            "staging": 1.0,
            "production": 1.3,
        }

    def assess(self, container, vuln_result, misconfigs, anomaly):
        severity_map = {"LOW": 10, "MEDIUM": 20, "HIGH": 35, "CRITICAL": 55, "UNKNOWN": 10}

        vulnerability_score = 0.0
        if vuln_result is not None:
            for finding in getattr(vuln_result, "findings", []) or []:
                vulnerability_score += severity_map.get(str(getattr(finding, "severity", "UNKNOWN")).upper(), 10)
            vulnerability_score = min(vulnerability_score, 100.0)

        privilege_score = 0.0
        if getattr(container, "privileged", False):
            privilege_score += 25.0
        if getattr(container, "run_as_root", False):
            privilege_score += 20.0
        if getattr(container, "host_network", False):
            privilege_score += 15.0
        if getattr(container, "host_pid", False):
            privilege_score += 15.0

        exposure_score = 0.0
        if getattr(container, "exposed_publicly", False):
            exposure_score += 30.0
        if getattr(container, "environment", "production") in self.environment_multipliers:
            exposure_score *= self.environment_multipliers[container.environment]

        config_score = 0.0
        for item in misconfigs or []:
            severity = str(item.get("severity", "low")).upper()
            config_score += severity_map.get(severity, 10)

        anomaly_score = float(anomaly) if isinstance(anomaly, (int, float)) else 0.0
        total = vulnerability_score + privilege_score + exposure_score + config_score + anomaly_score
        normalized = min(100.0, max(0.0, total))

        if normalized >= 80:
            classification = "Critical"
        elif normalized >= 65:
            classification = "High"
        elif normalized >= 40:
            classification = "Medium"
        else:
            classification = "Low"

        return Assessment(
            classification=classification,
            normalized_score=round(normalized, 2),
            vulnerability_score=round(vulnerability_score, 2),
            privilege_score=round(privilege_score, 2),
            exposure_score=round(exposure_score, 2),
            anomaly_score=round(anomaly_score, 2),
        )
