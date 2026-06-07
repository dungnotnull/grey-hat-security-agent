"""Docker PoC sandbox executor for CVE proof-of-concept code.

Runs PoC code in an isolated Docker container with:
- --network none (no network access)
- Read-only filesystem
- Memory and CPU limits
- Auto-destroyed after run

Requires valid AuthToken for target.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    """Result of a sandbox execution."""
    execution_id: str
    cve_id: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    duration_seconds: float = 0.0
    safe: bool = True  # Whether the container was safely destroyed


class DockerSandbox:
    """Execute CVE PoC code in an isolated Docker container."""

    BASE_IMAGE = "python:3.11-slim"
    MEMORY_LIMIT = "128m"
    CPU_LIMIT = 0.5
    DEFAULT_TIMEOUT = 30

    def __init__(self):
        self._client = None

    def _get_client(self):
        """Lazily initialize Docker client."""
        if self._client is None:
            try:
                import docker
                self._client = docker.from_env()
            except Exception as e:
                logger.error(f"Docker not available: {e}")
                raise RuntimeError(f"Docker is not available: {e}")
        return self._client

    def run_in_sandbox(
        self,
        script: str,
        cve_id: str = "",
        timeout: int = 30,
        language: str = "python",
    ) -> SandboxResult:
        """Execute a script in an isolated Docker container.

        Args:
            script: Script content to execute.
            cve_id: CVE ID being tested.
            timeout: Execution timeout in seconds.
            language: Script language (python, bash).

        Returns:
            SandboxResult with execution output and metadata.
        """
        execution_id = str(uuid.uuid4())
        result = SandboxResult(
            execution_id=execution_id,
            cve_id=cve_id,
        )

        try:
            client = self._get_client()
            start_time = datetime.now(timezone.utc)

            # Determine command based on language
            if language == "python":
                command = f"python3 -c {json.dumps(script)}"
            elif language == "bash":
                command = f"bash -c {json.dumps(script)}"
            else:
                command = f"python3 -c {json.dumps(script)}"

            # Run container with strict isolation
            container = client.containers.run(
                image=self.BASE_IMAGE,
                command=command,
                network_mode="none",          # No network access
                mem_limit=self.MEMORY_LIMIT,  # 128MB memory limit
                nano_cpus=int(self.CPU_LIMIT * 1e9),  # 0.5 CPU
                read_only=True,               # Read-only filesystem
                tmpfs={"/tmp": "size=10m"},   # Small writable /tmp
                detach=True,
                remove=False,
                labels={
                    "grey-hat-agent": "true",
                    "execution-id": execution_id,
                    "cve-id": cve_id,
                },
                hostname=f"sandbox-{execution_id[:8]}",
            )

            # Wait for container to finish
            try:
                container.wait(timeout=timeout)
                result.timed_out = False
            except Exception:
                result.timed_out = True
                logger.warning(f"Sandbox execution timed out after {timeout}s for {cve_id}")

            # Get logs
            try:
                result.stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                result.stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
            except Exception:
                pass

            # Get exit code
            try:
                container_info = container.attrs
                result.exit_code = container_info.get("State", {}).get("ExitCode", -1)
            except Exception:
                pass

            # Calculate duration
            end_time = datetime.now(timezone.utc)
            result.duration_seconds = (end_time - start_time).total_seconds()

            # Safely destroy the container
            try:
                container.remove(force=True)
                result.safe = True
                logger.info(f"Sandbox container destroyed: {execution_id}")
            except Exception as e:
                result.safe = False
                logger.warning(f"Failed to destroy sandbox container {execution_id}: {e}")

        except RuntimeError as e:
            result.stderr = str(e)
            result.safe = False
        except Exception as e:
            result.stderr = f"Sandbox error: {e}"
            result.safe = False
            logger.error(f"Sandbox execution failed for {cve_id}: {e}")

        return result

    def check_availability(self) -> bool:
        """Check if Docker is available and the sandbox image exists."""
        try:
            client = self._get_client()
            client.images.get(self.BASE_IMAGE)
            return True
        except Exception:
            try:
                # Try to pull the image
                client = self._get_client()
                client.images.pull(self.BASE_IMAGE)
                return True
            except Exception as e:
                logger.warning(f"Docker sandbox not available: {e}")
                return False

    def cleanup_orphaned_containers(self) -> int:
        """Remove any orphaned sandbox containers.

        Returns:
            Number of containers removed.
        """
        count = 0
        try:
            client = self._get_client()
            containers = client.containers.list(all=True, filters={"label": "grey-hat-agent=true"})
            for container in containers:
                try:
                    container.remove(force=True)
                    count += 1
                    logger.info(f"Removed orphaned container: {container.id[:12]}")
                except Exception as e:
                    logger.warning(f"Failed to remove container {container.id[:12]}: {e}")
        except Exception as e:
            logger.error(f"Failed to cleanup orphaned containers: {e}")
        return count
