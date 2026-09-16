#!/usr/bin/env python3
"""Export config/soar_policy.ncl → config/soar_policy.json (requires nickel on PATH)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NCL = ROOT / "config" / "soar_policy.ncl"
JSON_OUT = ROOT / "config" / "soar_policy.json"


def main() -> int:
    nickel = shutil.which("nickel")
    if not nickel:
        print("nickel not found on PATH. Install from https://github.com/nickel-lang/nickel/releases", file=sys.stderr)
        return 1
    if not NCL.is_file():
        print(f"missing {NCL}", file=sys.stderr)
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

    data = json.loads(proc.stdout)
    JSON_OUT.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {JSON_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
