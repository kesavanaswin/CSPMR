import json

from engines.analysis_engine import PolicyEngine
from engines.risk_engine import RiskEngine
from integrations.falco_stream import FalcoStream
from utils.models import ContainerConfig


def test_falco_normalization():
    raw = {
        "rule": "Terminal shell in container",
        "priority": "Warning",
        "output": "shell spawned",
        "output_fields": {
            "container.id": "abc123",
            "evt.type": "execve",
        },
    }
    event = FalcoStream.normalize(raw)
    assert event.container_id == "abc123"
    assert event.suspicious is True
    assert event.event_type == "Terminal shell in container"


def test_policy_and_risk_runtime_interfaces():
    policy = PolicyEngine("config/policies.yaml")
    risk = RiskEngine(policy.environment_multipliers)
    container = ContainerConfig(
        container_id="abc123",
        image="nginx:latest",
        namespace="default",
        privileged=False,
        run_as_root=True,
        host_network=False,
        host_pid=False,
        cpu_limit=None,
        memory_limit=None,
        exposed_publicly=False,
        environment="production",
    )
    misconfigs = policy.evaluate(container)
    assessment = risk.assess(container, None, misconfigs, None)
    assert assessment.classification in {"Low", "Medium", "High", "Critical"}
    assert 0 <= assessment.normalized_score <= 100
