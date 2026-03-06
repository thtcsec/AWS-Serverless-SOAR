from typing import Protocol, Any, Dict
from pydantic import BaseModel

class Playbook(Protocol):
    """Protocol defining the interface for all SOAR Playbooks."""
    
    def can_handle(self, event_data: Dict[str, Any]) -> bool:
        """Determines if the playbook can handle the given event source/type."""
        ...

    def execute(self, event_data: Dict[str, Any]) -> bool:
        """Executes the remediation playbook."""
        ...
