"""
AWS SOAR — Process-Level Containment via SSM
Enables granular containment by listing and killing malicious processes
on EC2 instances using AWS Systems Manager (SSM) Run Command,
instead of the coarse-grained Network isolation approach.

Containment Hierarchy: Function > Process > Permissions > Network
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aws-soar.process_containment")


class ProcessContainment:
    """Manage process-level containment on EC2 instances via SSM."""

    def __init__(self, ssm_client: Any) -> None:
        self._ssm = ssm_client

    def list_processes(self, instance_id: str) -> List[Dict[str, str]]:
        """List running processes on the target EC2 instance."""
        command = "ps aux --sort=-%cpu | head -50"
        output = self._run_command(instance_id, command)
        if not output:
            return []

        processes: List[Dict[str, str]] = []
        lines = output.strip().split("\n")
        for line in lines[1:]:  # Skip header
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "cpu": parts[2],
                    "mem": parts[3],
                    "command": parts[10],
                })
        return processes

    def kill_process(self, instance_id: str, pid: str) -> bool:
        """Kill a specific process by PID on the target instance."""
        command = f"kill -9 {pid} && echo 'KILLED' || echo 'FAILED'"
        output = self._run_command(instance_id, command)
        return output is not None and "KILLED" in output

    def kill_by_name(self, instance_id: str, process_name: str) -> bool:
        """Kill all processes matching a name (e.g. 'xmrig', 'cryptominer')."""
        safe_name = process_name.replace("'", "")
        command = f"pkill -9 -f '{safe_name}' && echo 'KILLED' || echo 'NO_MATCH'"
        output = self._run_command(instance_id, command)
        return output is not None and "KILLED" in output

    def quarantine_file(self, instance_id: str, file_path: str) -> bool:
        """Move a suspicious file to a quarantine directory."""
        commands = [
            "mkdir -p /var/quarantine",
            f"chmod 000 '{file_path}'",
            f"mv '{file_path}' /var/quarantine/",
        ]
        command = " && ".join(commands) + " && echo 'QUARANTINED'"
        output = self._run_command(instance_id, command)
        return output is not None and "QUARANTINED" in output

    def get_containment_report(
        self, instance_id: str
    ) -> Dict[str, Any]:
        """Generate a containment status report for the instance."""
        processes = self.list_processes(instance_id)

        suspicious_keywords = [
            "xmrig", "cryptominer", "minerd", "coinhive",
            "kinsing", "kdevtmpfsi", "ld-linux",
        ]
        suspicious = [
            p for p in processes
            if any(kw in p.get("command", "").lower() for kw in suspicious_keywords)
        ]

        return {
            "instance_id": instance_id,
            "total_processes": len(processes),
            "suspicious_processes": suspicious,
            "suspicious_count": len(suspicious),
            "top_cpu_processes": processes[:5],
        }

    def _run_command(self, instance_id: str, command: str) -> Optional[str]:
        """Execute a shell command on EC2 via SSM Run Command."""
        try:
            response = self._ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [command]},
                TimeoutSeconds=30,
            )
            command_id = response["Command"]["CommandId"]

            # Poll for completion
            for _ in range(10):
                time.sleep(2)
                result = self._ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id,
                )
                status = result.get("Status", "")
                if status == "Success":
                    return result.get("StandardOutputContent", "")
                elif status in ("Failed", "TimedOut", "Cancelled"):
                    logger.error(
                        f"SSM command failed on {instance_id}: "
                        f"{result.get('StandardErrorContent', '')}"
                    )
                    return None

            logger.error(f"SSM command timed out on {instance_id}")
            return None
        except Exception as e:
            logger.error(f"SSM execution error on {instance_id}: {e}")
            return None
