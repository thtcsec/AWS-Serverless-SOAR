from typing import Any

from src.core.event_normalizer import EventNormalizer, UnifiedIncident
from src.core.logger import logger
from src.playbooks.base import Playbook


class PlaybookRegistry:
    """Registry to load and dispatch the correct playbook for an incident."""

    def __init__(self) -> None:
        self._playbooks: list[Playbook] = []

    def register(self, playbook: Playbook) -> None:
        self._playbooks.append(playbook)
        logger.info(f"Registered playbook: {playbook.__class__.__name__}")

    def dispatch(self, incident: UnifiedIncident | dict[str, Any]) -> bool | dict[str, Any] | None:
        """Finds the applicable playbook and executes it."""
        unified = EventNormalizer.ensure(incident)
        for playbook in self._playbooks:
            if playbook.can_handle(unified):
                logger.info(f"Dispatching event to {playbook.__class__.__name__}")
                return playbook.execute(unified)

        logger.warning(f"No playbook registered to handle incident {unified.incident_id}")
        return None

    @property
    def playbooks(self) -> list[Playbook]:
        return list(self._playbooks)


registry = PlaybookRegistry()
