from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Dict, List, Optional


def scan_image(image: str, force: bool = False) -> Dict[str, Any]:
    """Minimal Trivy adapter used by the realtime upgrade.

    If Trivy is not present, this returns a structured "skipped" result so the
    higher-level code can continue without crashing.
    """
    if not image:
        return {"skipped": True, "reason": "empty image", "findings": []}

    trivy = shutil.which("trivy")
    if not trivy:
        return {"skipped": True, "reason": "trivy binary not found on PATH", "findings": []}

    cmd = [trivy, "image", "--format", "json", "--quiet", image]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError:
        return {"skipped": True, "reason": "trivy runtime unavailable", "findings": []}

    if result.returncode != 0:
        return {"skipped": True, "reason": result.stderr.strip() or "trivy scan failed", "findings": []}

    stdout = (result.stdout or "").strip()
    if not stdout:
        return {"skipped": True, "reason": "trivy returned no output", "findings": []}

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return {"skipped": True, "reason": "trivy returned non-JSON output", "findings": []}

    findings: List[Dict[str, Any]] = []
    for item in payload.get("Results", []) or []:
        for vuln in item.get("Vulnerabilities", []) or []:
            findings.append({
                "cve_id": vuln.get("VulnerabilityID") or "UNKNOWN",
                "package": vuln.get("PkgName") or "UNKNOWN",
                "severity": (vuln.get("Severity") or "UNKNOWN").upper(),
                "fixed_version": vuln.get("FixedVersion") or "",
            })
    return {"skipped": False, "findings": findings}
