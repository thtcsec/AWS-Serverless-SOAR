"""Run Python CI gates from any working directory using the current interpreter."""

import argparse
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-nickel", action="store_true", help="Skip policy export validation locally")
    parser.add_argument("--skip-audit", action="store_true", help="Skip network dependency audit locally")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root)
    env.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    commands = []
    if not args.skip_nickel:
        commands.append([sys.executable, "scripts/check_ncl_export.py"])
    modules = [
        ["ruff", "check", "src", "tests"],
        ["ruff", "format", "--check", "src", "tests"],
        ["bandit", "-r", "src", "-ll", "-ii"],
        ["mypy", "src", "--ignore-missing-imports"],
        ["pytest", "tests/", "--cov=src", "--cov-report=xml"],
    ]
    if not args.skip_audit:
        modules.append(["pip_audit", "-r", "requirements.txt", "--ignore-vuln", "CVE-2024-23342"])
    commands.extend([sys.executable, "-m", *module] for module in modules)
    for command in commands:
        print("+ " + " ".join(command), flush=True)
        result = subprocess.run(command, cwd=root, env=env, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
