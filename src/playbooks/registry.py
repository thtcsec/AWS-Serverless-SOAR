from typing import Any

from src.core.logger import logger
from src.playbooks.base import Playbook


class PlaybookRegistry:
    """Registry to load and dispatch the correct playbook for an event."""

    def __init__(self):
        self._playbooks: list[Playbook] = []

    def register(self, playbook: Playbook) -> None:
        self._playbooks.append(playbook)

    def dispatch(self, event_data: dict[str, Any]) -> bool:
        """Finds the applicable playbook and executes it."""
        for playbook in self._playbooks:
            if playbook.can_handle(event_data):
                logger.info(f"Dispatching event to {playbook.__class__.__name__}")
                return playbook.execute(event_data)

        logger.warning("No playbook registered to handle this event type.")
        return False


# Global registry
registry = PlaybookRegistry()
