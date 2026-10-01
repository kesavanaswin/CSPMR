import json
from types import SimpleNamespace

from engines.mitigation_engine import MitigationEngine
from realtime_cspm import RealtimeCSPM


def test_mitigation_writes_real_container_id(tmp_path):
    alerts_path = tmp_path / "alerts.json"
    webhook_path = tmp_path / "webhook.json"
    engine = MitigationEngine(str(alerts_path), str(webhook_path))
    assessment = SimpleNamespace(classification="High", normalized_score=82.0)

    alert = engine.process(assessment, "abc123")

    assert alert.container_id == "abc123"
    payload = json.loads(alerts_path.read_text(encoding="utf-8"))
    assert payload[-1]["container_id"] == "abc123"


def test_discover_handles_missing_docker(monkeypatch, tmp_path):
    app = RealtimeCSPM(str(tmp_path / "falco.jsonl"))

    monkeypatch.setattr(app.docker, "available", lambda: False)

    app.discover()

    assert app.report_path and json.loads(open(app.report_path, encoding="utf-8").read()) == []
