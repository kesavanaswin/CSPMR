"""Minimal Kubernetes ValidatingAdmissionWebhook server.

This endpoint evaluates Pod admission requests using the existing CSPM policy
and risk engine. It is intentionally stateless. TLS termination should be
provided by Kubernetes/Ingress or the webhook deployment.
"""
from __future__ import annotations
import json
import os
from flask import Flask, jsonify, request

from engines.analysis_engine import PolicyEngine
from engines.risk_engine import RiskEngine
from utils.models import ContainerConfig

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY = os.path.join(BASE_DIR, "config", "policies.yaml")

app = Flask(__name__)
policy = PolicyEngine(POLICY)
risk = RiskEngine(policy.environment_multipliers)


def pod_to_container(pod: dict) -> ContainerConfig:
    metadata = pod.get("metadata") or {}
    spec = pod.get("spec") or {}
    containers = spec.get("containers") or []
    first = containers[0] if containers else {}
    sc = first.get("securityContext") or {}
    pod_sc = spec.get("securityContext") or {}
    run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
    privileged = bool(sc.get("privileged", False))
    host_network = bool(spec.get("hostNetwork", False))
    host_pid = bool(spec.get("hostPID", False))
    resources = first.get("resources") or {}
    limits = resources.get("limits") or {}
    namespace = metadata.get("namespace") or "default"
    labels = metadata.get("labels") or {}

    return ContainerConfig(
        container_id=metadata.get("uid") or metadata.get("name") or "admission-request",
        image=first.get("image") or "",
        namespace=namespace,
        privileged=privileged,
        run_as_root=(run_as_user in (None, 0)),
        host_network=host_network,
        host_pid=host_pid,
        cpu_limit=str(limits.get("cpu")) if limits.get("cpu") is not None else None,
        memory_limit=str(limits.get("memory")) if limits.get("memory") is not None else None,
        exposed_publicly=bool(labels.get("cspm.public") == "true"),
        environment=labels.get("cspm.environment") or "production",
    )


@app.post("/validate")
def validate():
    review = request.get_json(force=True)
    uid = (review.get("request") or {}).get("uid", "")
    resource = (review.get("request") or {}).get("object") or {}
    container = pod_to_container(resource)
    misconfigs = policy.evaluate(container)
    assessment = risk.assess(container, None, misconfigs, None)

    allowed = assessment.classification != "Critical"
    response = {
        "uid": uid,
        "allowed": allowed,
        "status": {} if allowed else {
            "code": 403,
            "message": (
                f"CSPM denied Pod: risk={assessment.normalized_score}/100 "
                f"classification={assessment.classification}"
            ),
        },
    }
    return jsonify({
        "apiVersion": review.get("apiVersion", "admission.k8s.io/v1"),
        "kind": "AdmissionReview",
        "response": response,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8443")))
