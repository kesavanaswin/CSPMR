"""Live Docker Engine event and container-state collector.

Uses the Docker CLI so the CSPM remains lightweight and works anywhere the
Docker CLI is available. Events are normalized into the existing CSPM models.
"""
from __future__ import annotations
import json
import shutil
import subprocess
from typing import Dict, Iterator, Optional

from utils.models import ContainerConfig


class DockerCollector:
    def __init__(self, docker_binary: str = "docker", timeout: int = 15):
        self.docker = docker_binary
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(self.docker) is not None

    def _run(self, *args: str) -> str:
        p = subprocess.run(
            [self.docker, *args],
            capture_output=True, text=True, timeout=self.timeout
        )
        if p.returncode != 0:
            raise RuntimeError(p.stderr.strip() or "docker command failed")
        return p.stdout.strip()

    def list_containers(self):
        raw = self._run("ps", "-a", "--format", "{{json .}}")
        for line in raw.splitlines():
            if line.strip():
                yield json.loads(line)

    def inspect(self, container_id: str) -> ContainerConfig:
        raw = self._run("inspect", container_id)
        obj = json.loads(raw)[0]
        cfg = obj.get("Config", {})
        host = obj.get("HostConfig", {})
        state = obj.get("State", {})
        ports = cfg.get("ExposedPorts") or {}
        bindings = host.get("PortBindings") or {}
        published = bool(bindings) or bool(ports and any(bindings.get(p) for p in ports))
        user = str(cfg.get("User") or "").strip()
        labels = cfg.get("Labels") or {}
        environment = (
            labels.get("cspm.environment")
            or labels.get("environment")
            or "production"
        )
        name = (obj.get("Name") or container_id).lstrip("/")
        namespace = labels.get("com.docker.compose.project") or "docker"

        cpu_limit = None
        mem_limit = None
        if host.get("NanoCpus"):
            cpu_limit = str(host["NanoCpus"])
        if host.get("Memory"):
            mem_limit = str(host["Memory"])

        return ContainerConfig(
            container_id=obj.get("Id", container_id)[:64],
            image=cfg.get("Image", ""),
            namespace=namespace,
            privileged=bool(host.get("Privileged", False)),
            run_as_root=(user in ("", "0", "root")),
            host_network=(host.get("NetworkMode") == "host"),
            host_pid=bool(host.get("PidMode") == "host"),
            cpu_limit=cpu_limit,
            memory_limit=mem_limit,
            exposed_publicly=published,
            environment=environment,
        )

    def stream(self) -> Iterator[Dict]:
        """Stream container lifecycle events until interrupted."""
        p = subprocess.Popen(
            [
                self.docker, "events",
                "--format", "{{json .}}",
                "--filter", "type=container",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        try:
            assert p.stdout is not None
            for line in p.stdout:
                if line.strip():
                    yield json.loads(line)
        finally:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()

    def event_container_id(self, event: Dict) -> Optional[str]:
        actor = event.get("Actor") or {}
        return actor.get("ID") or actor.get("Attributes", {}).get("name")
