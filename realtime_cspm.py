#!/usr/bin/env python3
"""True real-time CSPM runner.

Data sources:
  * Docker Engine lifecycle events + live container inspection
  * Trivy image vulnerability scanning
  * Falco JSON-line runtime alerts

Existing CSPM PolicyEngine, AnomalyDetector, RiskEngine and MitigationEngine
are reused. The runner recomputes a container's posture when new state or
runtime telemetry arrives.
"""
from __future__ import annotations
import argparse
import os
import signal
import threading
from collections import defaultdict, deque
from typing import Dict, List

from engines.analysis_engine import PolicyEngine, AnomalyDetector
from engines.risk_engine import RiskEngine
from engines.mitigation_engine import MitigationEngine
from integrations.docker_events import DockerCollector
from integrations.falco_stream import FalcoStream
from integrations.trivy_adapter import scan_container
from integrations.notifications import WebhookNotifier
from utils.models import ContainerConfig, RuntimeEvent
from utils.logger import get_logger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_PATH = os.path.join(BASE_DIR, "config", "policies.yaml")
ALERTS = os.path.join(BASE_DIR, "output", "alerts.json")
WEBHOOKS = os.path.join(BASE_DIR, "output", "webhook_notifications.json")

log = get_logger("realtime")


class RealtimeCSPM:
    def __init__(self, falco_path: str, rescan_images: bool = False):
        self.docker = DockerCollector()
        self.falco = FalcoStream(falco_path)
        self.policy = PolicyEngine(POLICY_PATH)
        self.anomaly = AnomalyDetector(contamination=0.25)
        self.risk = RiskEngine(self.policy.environment_multipliers)
        self.mitigation = MitigationEngine(ALERTS, WEBHOOKS)
        self.notifier = WebhookNotifier()
        self.rescan_images = rescan_images
        self.containers: Dict[str, ContainerConfig] = {}
        self.vulns = {}
        self.events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._stop = threading.Event()
        self._seen_alert_state = {}

    def stop(self, *_):
        self._stop.set()

    def discover(self):
        for item in self.docker.list_containers():
            cid = item.get("ID")
            if not cid:
                continue
            try:
                self.refresh_container(cid)
            except Exception as exc:
                log.warning("Initial container refresh failed for %s: %s", cid, exc)

    def refresh_container(self, cid: str):
        container = self.docker.inspect(cid)
        self.containers[container.container_id] = container
        try:
            vuln = scan_container(container, force=self.rescan_images)
            if vuln is not None:
                self.vulns[container.container_id] = vuln
        except Exception as exc:
            log.warning("Trivy scan failed for %s: %s", container.image, exc)
        self.evaluate(container.container_id)

    def evaluate(self, cid: str):
        container = self.containers.get(cid)
        if not container:
            return

        events = list(self.events.get(cid, []))
        # Include other known containers so IsolationForest has a population.
        all_events: List[RuntimeEvent] = []
        for values in self.events.values():
            all_events.extend(values)
        anomaly_map = self.anomaly.analyze(all_events)
        anomaly = anomaly_map.get(cid)

        misconfigs = self.policy.evaluate(container)
        assessment = self.risk.assess(
            container=container,
            vuln_result=self.vulns.get(cid),
            misconfigs=misconfigs,
            anomaly=anomaly,
        )

        state = (assessment.classification, round(assessment.normalized_score, 2))
        print(
            f"[CSPM] {cid[:12]:<12} "
            f"risk={assessment.normalized_score:6.2f} "
            f"class={assessment.classification:<8} "
            f"vuln={assessment.vulnerability_score:<2} "
            f"priv={assessment.privilege_score} "
            f"exp={assessment.exposure_score}"
        )

        # Avoid generating identical alerts for every repeated runtime event.
        if self._seen_alert_state.get(cid) != state:
            alert = self.mitigation.process(assessment)
            self._seen_alert_state[cid] = state
            if assessment.classification in {"High", "Critical"}:
                try:
                    result = self.notifier.send(alert)
                    if result.get("sent"):
                        print(f"[CSPM] webhook delivered for {cid[:12]}")
                except Exception as exc:
                    log.warning("Webhook delivery failed: %s", exc)

    def docker_loop(self):
        if not self.docker.available():
            raise RuntimeError("Docker CLI is not available on PATH")
        for event in self.docker.stream():
            if self._stop.is_set():
                return
            action = str(event.get("Action") or event.get("status") or "").lower()
            cid = self.docker.event_container_id(event)
            if not cid:
                continue
            if action in {"start", "create", "restart", "health_status: healthy", "health_status: unhealthy"}:
                try:
                    self.refresh_container(cid)
                except Exception as exc:
                    log.warning("Docker refresh failed for %s: %s", cid, exc)
            elif action in {"destroy", "die", "stop"}:
                key = next((k for k in self.containers if k.startswith(cid)), cid)
                print(f"[CSPM] Docker lifecycle: {action} {cid[:12]}")
                if action == "destroy":
                    self.containers.pop(key, None)
                    self.vulns.pop(key, None)
                    self.events.pop(key, None)

    def falco_loop(self):
        for event in self.falco.stream():
            if self._stop.is_set():
                return
            cid = event.container_id
            # Falco may emit a container name rather than ID. Resolve by exact
            # container id first, then by a short/name suffix where possible.
            resolved = cid
            if cid not in self.containers:
                matches = [k for k in self.containers if k.startswith(cid)]
                if matches:
                    resolved = matches[0]
            event.container_id = resolved
            self.events[resolved].append(event)
            print(
                f"[FALCO] {resolved[:12]:<12} "
                f"{event.event_type} suspicious={event.suspicious}"
            )
            self.evaluate(resolved)

    def run(self):
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        self.discover()

        threads = [
            threading.Thread(target=self.docker_loop, name="docker-events", daemon=True),
            threading.Thread(target=self.falco_loop, name="falco-events", daemon=True),
        ]
        for t in threads:
            t.start()

        print("[CSPM] Real-time monitoring is active. Press Ctrl+C to stop.")
        print("[CSPM] Sources: Docker events + Trivy + Falco")
        while not self._stop.wait(1):
            pass
        print("[CSPM] Stopping...")


def main():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--falco-log",
        default=os.getenv(
            "CSPM_FALCO_LOG",
            os.path.join(BASE_DIR, "samples", "falco_events.jsonl"),
        ),
    )
    p.add_argument("--rescan", action="store_true", help="force Trivy rescans")
    args = p.parse_args()

    app = RealtimeCSPM(args.falco_log, args.rescan)
    app.run()


if __name__ == "__main__":
    main()
