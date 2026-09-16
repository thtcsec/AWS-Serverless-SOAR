"""
Load SOAR policy bands from the Nickel-exported JSON artifact.

Source of truth: config/soar_policy.ncl
Runtime artifact: config/soar_policy.json
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_DEFAULTS: dict[str, Any] = {
    "schema_version": 1,
    "ignore_threshold": 40.0,
    "auto_isolate_threshold": 70.0,
    "anomaly_boost": 15.0,
    "anomaly_flag_threshold": -0.5,
}

_REQUIRED = (
    "ignore_threshold",
    "auto_isolate_threshold",
    "anomaly_boost",
    "anomaly_flag_threshold",
)


def policy_json_path() -> Path:
    """Repo-root config/soar_policy.json relative to this module."""
    return Path(__file__).resolve().parents[2] / "config" / "soar_policy.json"


def policy_ncl_path() -> Path:
    return Path(__file__).resolve().parents[2] / "config" / "soar_policy.ncl"


@lru_cache(maxsize=1)
def get_policy_config() -> dict[str, float | int]:
    """Return validated policy config (defaults if JSON missing)."""
    path = policy_json_path()
    data: dict[str, Any] = dict(_DEFAULTS)
    if path.is_file():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError(f"Invalid policy config (expected object): {path}")
        data.update(loaded)

    for key in _REQUIRED:
        if key not in data:
            raise KeyError(f"Missing policy key '{key}' in {path}")
        data[key] = float(data[key])

    data["schema_version"] = int(data.get("schema_version", 1))
    if data["ignore_threshold"] >= data["auto_isolate_threshold"]:
        raise ValueError("ignore_threshold must be < auto_isolate_threshold")
    return data  # type: ignore[return-value]


def reload_policy_config() -> dict[str, float | int]:
    get_policy_config.cache_clear()
    return get_policy_config()
