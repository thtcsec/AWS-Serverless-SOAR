from typing import Any, Protocol

from src.core.event_normalizer import UnifiedIncident


class Playbook(Protocol):
    """Protocol defining the interface for all SOAR Playbooks."""

    def can_handle(self, incident: UnifiedIncident | dict[str, Any]) -> bool:
        """Determines if the playbook can handle the given incident."""
        ...

    def execute(self, incident: UnifiedIncident | dict[str, Any]) -> bool | dict[str, Any]:
        """Executes the remediation playbook."""
        ...
