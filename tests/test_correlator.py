"""Tests for AWS Incident Correlator."""
import pytest
from src.core.event_normalizer import UnifiedIncident
from src.core.correlator import IncidentCorrelator


class TestIncidentCorrelator:
    @pytest.fixture
    def correlator(self):
        return IncidentCorrelator()

    @pytest.fixture
    def incident_a(self):
        return UnifiedIncident(
            incident_id="inc-001",
            source_ip="198.51.100.1",
            actor="attacker@evil.com",
            timestamp="2026-03-10T00:00:00Z",
            action="CreateAccessKey",
        )

    @pytest.fixture
    def incident_b(self):
        return UnifiedIncident(
            incident_id="inc-002",
            source_ip="198.51.100.1",
            actor="different-actor",
            timestamp="2026-03-10T00:03:00Z",
            action="GetObject",
        )

    @pytest.fixture
    def incident_c(self):
        return UnifiedIncident(
            incident_id="inc-003",
            source_ip="10.0.0.99",
            actor="attacker@evil.com",
            timestamp="2026-03-10T00:02:00Z",
            action="PutBucketPolicy",
        )

    def test_ingest_and_find_by_ip(self, correlator, incident_a, incident_b):
        correlator.ingest(incident_a)
        correlator.ingest(incident_b)

        related = correlator.find_related("inc-001")
        assert len(related) == 1
        assert related[0].incident_id == "inc-002"

    def test_ingest_and_find_by_actor(self, correlator, incident_a, incident_c):
        correlator.ingest(incident_a)
        correlator.ingest(incident_c)

        related = correlator.find_related("inc-001")
        assert len(related) == 1
        assert related[0].incident_id == "inc-003"

    def test_no_related_for_unknown_id(self, correlator):
        assert correlator.find_related("nonexistent") == []

    def test_campaign_summary(self, correlator, incident_a, incident_b, incident_c):
        correlator.ingest(incident_a)
        correlator.ingest(incident_b)
        correlator.ingest(incident_c)

        campaigns = correlator.get_campaign_summary()
        assert len(campaigns) >= 1
        assert campaigns[0]["incident_count"] >= 2

    def test_time_window_exclusion(self, correlator):
        far_past = UnifiedIncident(
            incident_id="old-001",
            source_ip="198.51.100.1",
            timestamp="2020-01-01T00:00:00Z",
            action="OldEvent",
        )
        recent = UnifiedIncident(
            incident_id="new-001",
            source_ip="198.51.100.1",
            timestamp="2026-03-10T00:00:00Z",
            action="NewEvent",
        )
        correlator.ingest(far_past)
        correlator.ingest(recent)

        related = correlator.find_related("new-001")
        assert len(related) == 0  # Too far apart in time
