"""Unit tests for Nickel-backed SOAR policy config."""

import json

from src.core.policy_config import get_policy_config, policy_json_path, policy_ncl_path, reload_policy_config
from src.integrations.scoring import ScoringEngine


class TestPolicyConfig:
    def test_ncl_and_json_artifacts_exist(self):
        assert policy_ncl_path().is_file()
        assert policy_json_path().is_file()

    def test_json_matches_scoring_engine_thresholds(self):
        reload_policy_config()
        cfg = get_policy_config()
        assert cfg["ignore_threshold"] == ScoringEngine.IGNORE_THRESHOLD
        assert cfg["auto_isolate_threshold"] == ScoringEngine.AUTO_ISOLATE_THRESHOLD
        assert cfg["anomaly_boost"] == ScoringEngine.ANOMALY_BOOST
        assert cfg["anomaly_flag_threshold"] == ScoringEngine.ANOMALY_FLAG_THRESHOLD

    def test_json_schema_keys(self):
        raw = json.loads(policy_json_path().read_text(encoding="utf-8"))
        for key in (
            "schema_version",
            "ignore_threshold",
            "auto_isolate_threshold",
            "anomaly_boost",
            "anomaly_flag_threshold",
        ):
            assert key in raw

    def test_ncl_mentions_canonical_bands(self):
        text = policy_ncl_path().read_text(encoding="utf-8")
        assert "ignore_threshold" in text
        assert "auto_isolate_threshold" in text
        assert "40" in text
        assert "70" in text
