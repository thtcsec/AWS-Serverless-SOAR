from typing import Any, Protocol


class Playbook(Protocol):
    """Protocol defining the interface for all SOAR Playbooks."""

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        """Determines if the playbook can handle the given event source/type."""
        ...

    def execute(self, event_data: dict[str, Any]) -> bool | dict[str, Any]:
        """Executes the remediation playbook."""
        ...
