from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ContainerConfig:
    container_id: str
    image: str
    namespace: str = "default"
    privileged: bool = False
    run_as_root: bool = False
    host_network: bool = False
    host_pid: bool = False
    cpu_limit: Optional[str] = None
    memory_limit: Optional[str] = None
    exposed_publicly: bool = False
    environment: str = "production"


@dataclass
class RuntimeEvent:
    container_id: str
    event_type: str
    detail: str
    syscall: Optional[str] = None
    timestamp: str = ""
    suspicious: bool = False


@dataclass
class VulnFinding:
    cve_id: str
    package: str
    severity: str = "UNKNOWN"
    fixed_version: str = ""


@dataclass
class VulnScanResult:
    container_id: str
    image: str
    findings: List[VulnFinding] = field(default_factory=list)
    scanned_at: str = ""


@dataclass
class Alert:
    container_id: str
    classification: str
    risk_score: float
    action_taken: str
    factors: List[str]
    timestamp: str = ""
