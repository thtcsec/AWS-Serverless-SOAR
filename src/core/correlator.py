"""
AWS SOAR — Cross-Cloud Incident Correlator
Correlates security incidents based on shared IOCs such as IP addresses,
actor identities, and temporal proximity.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.core.event_normalizer import UnifiedIncident

logger = logging.getLogger("aws-soar.correlator")

# Time window for correlation (seconds)
CORRELATION_WINDOW_SECONDS = 300  # 5 minutes


class IncidentCorrelator:
    """In-memory incident log with IOC-based correlation."""

    def __init__(self) -> None:
        self._incidents: Dict[str, UnifiedIncident] = {}
        self._ip_index: Dict[str, List[str]] = defaultdict(list)
        self._actor_index: Dict[str, List[str]] = defaultdict(list)

    def ingest(self, incident: UnifiedIncident) -> None:
        """Add an incident to the correlation store."""
        iid = incident.incident_id
        self._incidents[iid] = incident

        if incident.source_ip:
            self._ip_index[incident.source_ip].append(iid)
        if incident.actor:
            self._actor_index[incident.actor].append(iid)

        logger.info(f"Ingested incident {iid} ({incident.raw_event_type})")

    def find_related(self, incident_id: str) -> List[UnifiedIncident]:
        """Find incidents related to the given incident by shared IOCs."""
        target = self._incidents.get(incident_id)
        if not target:
            return []

        related_ids: set[str] = set()

        # Match by IP
        if target.source_ip and target.source_ip in self._ip_index:
            related_ids.update(self._ip_index[target.source_ip])

        # Match by actor
        if target.actor and target.actor in self._actor_index:
            related_ids.update(self._actor_index[target.actor])

        # Remove self
        related_ids.discard(incident_id)

        # Filter by time proximity
        related = []
        for rid in related_ids:
            candidate = self._incidents[rid]
            if self._within_window(target, candidate):
                related.append(candidate)

        return related

    def get_campaign_summary(self) -> List[Dict[str, Any]]:
        """Group correlated incidents into potential attack campaigns."""
        visited: set[str] = set()
        campaigns: List[Dict[str, Any]] = []

        for iid in self._incidents:
            if iid in visited:
                continue

            cluster = self._build_cluster(iid, visited)
            if len(cluster) > 1:
                incidents = [self._incidents[c] for c in cluster]
                campaigns.append({
                    "campaign_id": f"CAMP-{iid[:8]}",
                    "incident_count": len(cluster),
                    "platforms": list({i.platform for i in incidents}),
                    "actors": list({i.actor for i in incidents if i.actor}),
                    "source_ips": list({i.source_ip for i in incidents if i.source_ip}),
                    "severity": max((i.severity for i in incidents), key=self._severity_rank),
                    "incident_ids": cluster,
                })

        return campaigns

    def _build_cluster(self, start_id: str, visited: set[str]) -> List[str]:
        """BFS to find all transitively related incidents."""
        queue = [start_id]
        cluster: List[str] = []

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            cluster.append(current)

            for related in self.find_related(current):
                if related.incident_id not in visited:
                    queue.append(related.incident_id)

        return cluster

    @staticmethod
    def _within_window(a: UnifiedIncident, b: UnifiedIncident) -> bool:
        """Check if two incidents are within the correlation time window."""
        try:
            ts_a = datetime.fromisoformat(a.timestamp.replace("Z", "+00:00"))
            ts_b = datetime.fromisoformat(b.timestamp.replace("Z", "+00:00"))
            return abs((ts_a - ts_b).total_seconds()) <= CORRELATION_WINDOW_SECONDS
        except (ValueError, AttributeError):
            return True  # If timestamps can't be parsed, include by default

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(severity, 0)
