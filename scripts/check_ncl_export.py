#!/usr/bin/env python3
"""Ensure committed soar_policy.json matches `nickel export` of soar_policy.ncl."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NCL = ROOT / "config" / "soar_policy.ncl"
JSON_PATH = ROOT / "config" / "soar_policy.json"


def _canon(data: dict[str, Any]) -> dict[str, float | int]:
    return {
        "schema_version": int(data["schema_version"]),
        "ignore_threshold": float(data["ignore_threshold"]),
        "auto_isolate_threshold": float(data["auto_isolate_threshold"]),
        "anomaly_boost": float(data["anomaly_boost"]),
        "anomaly_flag_threshold": float(data["anomaly_flag_threshold"]),
    }


def main() -> int:
    nickel = shutil.which("nickel")
    if not nickel:
        print("nickel not found on PATH", file=sys.stderr)
        return 1
    if not NCL.is_file() or not JSON_PATH.is_file():
        print("missing config/soar_policy.ncl or config/soar_policy.json", file=sys.stderr)
        return 1

    proc = subprocess.run(
        [nickel, "export", str(NCL)],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stderr or proc.stdout, file=sys.stderr)
        return proc.returncode

    exported = _canon(json.loads(proc.stdout))
    committed = _canon(json.loads(JSON_PATH.read_text(encoding="utf-8")))
    if exported != committed:
        print("config/soar_policy.json is out of sync with soar_policy.ncl", file=sys.stderr)
        print("exported:", exported, file=sys.stderr)
        print("committed:", committed, file=sys.stderr)
        print("Run: python scripts/export_ncl_config.py", file=sys.stderr)
        return 1

    print("Nickel policy export matches committed JSON")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
