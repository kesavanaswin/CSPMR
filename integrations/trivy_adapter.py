"""Adapter from the project's Trivy CLI scanner to CSPM dataclasses."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional

from utils.models import ContainerConfig, VulnFinding, VulnScanResult
from vuln_scan import scan_image


def scan_container(container: ContainerConfig, force: bool = False) -> Optional[VulnScanResult]:
    result = scan_image(container.image, force=force)
    if result.get("skipped") and result.get("reason") == "trivy binary not found on PATH":
        return None

    findings = [
        VulnFinding(
            cve_id=f.get("cve_id") or "UNKNOWN",
            package=f.get("package") or "UNKNOWN",
            severity=f.get("severity") or "UNKNOWN",
            fixed_version=f.get("fixed_version") or "",
        )
        for f in result.get("findings", [])
    ]
    return VulnScanResult(
        container_id=container.container_id,
        image=container.image,
        findings=findings,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )
